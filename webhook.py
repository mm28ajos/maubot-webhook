# webhook.py — maubot-webhook (enhanced, RecursiveDict-safe, E2EE-safe)
#
# Endpoints (static):
#   POST /send
#   POST /send-image
#   POST /send-media   (NEW: general media endpoint, incl. video)
#
# Features:
#   - Text sending with optional markdown/html
#   - Image sending with encrypted attachments (Matrix E2EE media)
#   - Media sending (image/video/file) with encrypted attachments
#   - Optional encrypted thumbnail for images (Pillow)
#   - Best-effort Pillow install at startup (optional)
#
# Return codes:
#   - 200: success
#   - 401: auth failure
#   - 400: bad request (validation/template/etc.)
#   - 503: Matrix homeserver unreachable/timeouts/connection failures
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import binascii
import os
import tempfile
import asyncio
import base64
import subprocess
import sys
from io import BytesIO
from typing import Any, Dict, Optional, Tuple

import jinja2
from aiohttp import BasicAuth, hdrs
from aiohttp.client_exceptions import ClientError
from aiohttp.web import (
    HTTPBadRequest,
    HTTPServiceUnavailable,
    HTTPUnauthorized,
    Request,
    Response,
)

from maubot import Plugin
from maubot.handlers import web

from mautrix.crypto.attachments import encrypt_attachment
from mautrix.errors.base import MatrixConnectionError
from mautrix.types import EventType, Format
from mautrix.util import markdown as mx_markdown
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper

# Pillow (optional, for thumbnails)
Image = None

FFMPEG_OK = False

def _ensure_ffmpeg(logger) -> None:
    global FFMPEG_OK
    if FFMPEG_OK:
        return

    def has_ffmpeg() -> bool:
        try:
            subprocess.check_call(["ffmpeg", "-version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    if has_ffmpeg():
        FFMPEG_OK = True
        logger.info("ffmpeg available: video thumbnail extraction enabled")
        return

    logger.warning("ffmpeg not found. Attempting install via apk...")

    try:
        subprocess.check_call(
            ["apk", "add", "--no-cache", "ffmpeg"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except Exception as e:
        logger.exception("apk install ffmpeg failed: %r", e)
        FFMPEG_OK = False
        logger.warning("Continuing without video thumbnails.")
        return

    if has_ffmpeg():
        FFMPEG_OK = True
        logger.info("ffmpeg installed successfully via apk")
    else:
        FFMPEG_OK = False
        logger.warning("apk reported success but ffmpeg still not found; continuing without video thumbnails.")

def _ensure_pillow(logger) -> None:
    """
    Best-effort: import Pillow; if missing, attempt to install it via pip.
    In Docker deployments, best is to bake Pillow into the image.
    """
    global Image
    if Image is not None:
        return

    try:
        from PIL import Image as _Image  # type: ignore
        Image = _Image
        logger.info("Pillow available: thumbnail generation enabled")
        return
    except Exception:
        logger.warning("Pillow not found. Attempting pip install (best-effort)...")

    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-cache-dir", "Pillow"])
        from PIL import Image as _Image  # type: ignore
        Image = _Image
        logger.info("Pillow installed successfully: thumbnail generation enabled")
    except Exception as e:
        Image = None
        logger.warning("Failed to install Pillow automatically; continuing without thumbnails. Error: %r", e)


# ----------------------------
# Config (RecursiveDict-safe: no setdefault)
# ----------------------------

class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        base = helper.base  # RecursiveDict in your setup

        # ---- migrations ----
        if "auth_type" not in self and "auth_token" in self:
            base["auth_type"] = "Bearer"

        # RecursiveDict.get() requires default in your mautrix version
        if "message_format" not in self and self.get("markdown", False):
            base["message_format"] = "markdown"

        # ---- copy keys ----
        helper.copy("path")
        helper.copy("method")
        helper.copy("room")
        helper.copy("message")
        helper.copy("message_format")
        helper.copy("message_type")
        helper.copy("auth_type")
        helper.copy("auth_token")
        helper.copy("force_json")
        helper.copy("ignore_empty_messages")

        # ---- image/media keys ----
        helper.copy("image_path")
        helper.copy("image_method")
        helper.copy("image_room")
        helper.copy("image_caption")
        helper.copy("image_caption_format")
        helper.copy("max_upload_bytes")
        helper.copy("enable_base64_json")

        # ---- defaults (no setdefault!) ----
        def default(key: str, value: Any) -> None:
            if key not in base:
                base[key] = value

        default("path", "/send")
        default("method", "POST")

        default("room", "")
        default("message", "{{ body }}")
        default("message_format", "plaintext")  # plaintext|markdown|html
        default("message_type", "m.text")       # m.text|m.notice

        default("auth_type", "")                # "", Basic, Bearer
        default("auth_token", "")

        default("force_json", False)
        default("ignore_empty_messages", False)

        default("image_path", "/send-image")
        default("image_method", "POST")
        default("image_room", "")
        default("image_caption", "")
        default("image_caption_format", "plaintext")
        default("max_upload_bytes", 5 * 1024 * 1024)  # 5 MiB default (raise for video!)
        default("enable_base64_json", True)

        # ---- validation ----
        valid_formats = {"plaintext", "markdown", "html"}
        if base["message_format"] not in valid_formats:
            raise ValueError(f"Invalid message_format: {base['message_format']}")
        if base["image_caption_format"] not in valid_formats:
            raise ValueError(f"Invalid image_caption_format: {base['image_caption_format']}")

        valid_msgtypes = {"m.text", "m.notice"}
        if base["message_type"] not in valid_msgtypes:
            raise ValueError(f"Invalid message_type: {base['message_type']}")

        valid_auth_types = {"", "Basic", "Bearer"}
        if base["auth_type"] not in valid_auth_types:
            raise ValueError(f"Invalid auth_type: {base['auth_type']}")

        if not isinstance(base["max_upload_bytes"], int) or base["max_upload_bytes"] <= 0:
            raise ValueError("max_upload_bytes must be a positive integer")


# ----------------------------
# Plugin
# ----------------------------

class WebhookPlugin(Plugin):
    @classmethod
    def get_config_class(cls):
        return Config

    async def start(self) -> None:
        await super().start()
        self.config.load_and_update()

        self._jinja_env = jinja2.Environment(
            autoescape=True,
            undefined=jinja2.StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )

        _ensure_pillow(self.log)
        _ensure_ffmpeg(self.log)
        self.log.info("Webhook started: POST /send, /send-image, /send-media")

    async def reload(self) -> None:
        self.config.load_and_update()
        self.log.info("Webhook config reloaded")

    # ----------------------------
    # Helpers
    # ----------------------------

    def _check_auth(self, request: Request) -> None:
        auth_type = str(self.config.get("auth_type", "") or "").strip()
        if not auth_type:
            return

        token = str(self.config.get("auth_token", "") or "")

        if auth_type == "Bearer":
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                raise HTTPUnauthorized(text="Missing Bearer token")
            got = header[len("Bearer "):].strip()
            if got != token:
                raise HTTPUnauthorized(text="Invalid Bearer token")
            return

        if auth_type == "Basic":
            if ":" not in token:
                raise HTTPUnauthorized(text="Invalid Basic auth config (auth_token must be user:pass)")
            user, pwd = token.split(":", 1)
            auth_header = request.headers.get("Authorization", "")
            try:
                parsed = BasicAuth.decode(auth_header)
            except Exception:
                raise HTTPUnauthorized(text="Missing/invalid Basic auth header")
            if parsed.login != user or parsed.password != pwd:
                raise HTTPUnauthorized(text="Invalid Basic credentials")
            return

        raise HTTPUnauthorized(text="Invalid auth_type")

    async def _read_body_and_json(self, request: Request) -> Tuple[str, Optional[Dict[str, Any]]]:
        body_bytes = await request.read()
        try:
            body = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            body = ""

        json_data: Optional[Dict[str, Any]] = None
        content_type = (request.headers.get("Content-Type") or "").lower()
        force_json = bool(self.config.get("force_json", False))

        if force_json or content_type.startswith("application/json"):
            try:
                val = await request.json()
                if isinstance(val, dict):
                    json_data = val
            except Exception:
                json_data = None

        return body, json_data

    def _ctx(self, request: Request, body: str, json_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "body": body,
            "json": json_data,
            "query": dict(request.query),
            "path": dict(request.match_info),
            "headers": dict(request.headers),
        }

    def _render(self, template: str, ctx: Dict[str, Any]) -> str:
        if template is None:
            return ""
        t = self._jinja_env.from_string(str(template))
        return t.render(**ctx)

    def _build_text_content(self, body: str, fmt: str, msgtype: str) -> Dict[str, Any]:
        fmt = (fmt or "plaintext").lower().strip()

        if msgtype not in {"m.text", "m.notice"}:
            raise HTTPBadRequest(text="message_type must be m.text or m.notice")

        if fmt == "plaintext":
            return {"msgtype": msgtype, "body": body}

        if fmt == "html":
            return {
                "msgtype": msgtype,
                "body": body,
                "format": "org.matrix.custom.html",
                "formatted_body": body,
            }

        if fmt == "markdown":
            html = mx_markdown.render(body)
            return {
                "msgtype": msgtype,
                "body": body,
                "format": Format.HTML.value,
                "formatted_body": html,
            }

        raise HTTPBadRequest(text=f"Invalid message_format: {fmt}")

    # ---- Reachability classification (maps to 503) ----
    def _is_unreachable_exc(self, e: BaseException) -> bool:
        if isinstance(e, (MatrixConnectionError, asyncio.TimeoutError, ClientError)):
            return True
        # Handles import-path mismatch cases
        if e.__class__.__name__ == "MatrixConnectionError":
            return True
        return False

    async def _send_room_message(self, room_id: str, content: Dict[str, Any]) -> None:
        try:
            await self.client.send_message_event(
                room_id=room_id,
                event_type=EventType.ROOM_MESSAGE,
                content=content,
            )
        except Exception as e:
            if self._is_unreachable_exc(e):
                self.log.warning("Matrix unreachable: %s", e)
                raise HTTPServiceUnavailable(text=f"Matrix unreachable: {e}")
            self.log.exception("send_message_event failed for room %s", room_id)
            raise HTTPBadRequest(text=f"Failed to send message for {room_id}: {e!r}")

    async def _upload_media_compat(self, data: bytes, mimetype: str, filename: str):
        """
        mautrix upload_media signature differs between versions.
        Try common variants:
          - content_type=
          - mime_type=
          - positional (data, mimetype, filename)

        Connectivity failures are mapped to 503.
        """
        try:
            try:
                return await self.client.upload_media(data, content_type=mimetype, filename=filename)
            except TypeError:
                pass
            try:
                return await self.client.upload_media(data, mime_type=mimetype, filename=filename)
            except TypeError:
                pass
            return await self.client.upload_media(data, mimetype, filename)
        except Exception as e:
            if self._is_unreachable_exc(e):
                self.log.warning("Matrix unreachable during upload_media: %s", e)
                raise HTTPServiceUnavailable(text=f"Matrix unreachable (upload): {e}")
            self.log.exception("upload_media failed")
            raise HTTPBadRequest(text=f"Failed to upload media: {e!r}")

    def _jpeg_dimensions(self, data: bytes) -> Optional[Tuple[int, int]]:
        """Minimal JPEG dimension parser. Returns (width, height) or None."""
        try:
            if len(data) < 4 or data[0:2] != b"\xFF\xD8":
                return None

            i = 2
            while i + 3 < len(data):
                if data[i] != 0xFF:
                    i += 1
                    continue
                while i < len(data) and data[i] == 0xFF:
                    i += 1
                if i >= len(data):
                    break
                marker = data[i]
                i += 1

                if marker in (0xD9, 0xDA):  # EOI, SOS
                    break

                if i + 1 >= len(data):
                    break
                seglen = (data[i] << 8) + data[i + 1]
                if seglen < 2 or i + seglen - 2 > len(data):
                    break

                if marker in (
                    0xC0, 0xC1, 0xC2, 0xC3,
                    0xC5, 0xC6, 0xC7,
                    0xC9, 0xCA, 0xCB,
                    0xCD, 0xCE, 0xCF,
                ):
                    if i + 7 < len(data):
                        height = (data[i + 3] << 8) + data[i + 4]
                        width = (data[i + 5] << 8) + data[i + 6]
                        if width > 0 and height > 0:
                            return width, height

                i += seglen
            return None
        except Exception:
            return None

    def _mk_video_thumbnail_ffmpeg(self, video_bytes: bytes, max_side: int = 320) -> Optional[Tuple[bytes, int, int]]:
        """
        Extract a frame 1 second before the end of the video as JPEG using ffmpeg.
        Returns (jpeg_bytes, w, h) or None.
        """
        if not FFMPEG_OK:
            return None

        tmp_in = None

        def _get_duration_seconds(path: str) -> Optional[float]:
            # Prefer ffprobe (usually shipped with ffmpeg)
            try:
                p = subprocess.run(
                    [
                        "ffprobe",
                        "-v", "error",
                        "-show_entries", "format=duration",
                        "-of", "default=noprint_wrappers=1:nokey=1",
                        path,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    check=False,
                )
                if p.returncode == 0 and p.stdout:
                    s = p.stdout.decode("utf-8", "replace").strip()
                    dur = float(s)
                    if dur > 0:
                        return dur
            except Exception:
                pass

            # Fallback: parse "Duration: HH:MM:SS.xx" from ffmpeg stderr
            try:
                p = subprocess.run(
                    ["ffmpeg", "-hide_banner", "-i", path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    check=False,
                )
                text = (p.stderr or b"").decode("utf-8", "replace")
                marker = "Duration: "
                idx = text.find(marker)
                if idx != -1:
                    rest = text[idx + len(marker): idx + len(marker) + 16]  # "HH:MM:SS.xx"
                    parts = rest.split(",")[0].strip().split(":")
                    if len(parts) == 3:
                        hh = float(parts[0])
                        mm = float(parts[1])
                        ss = float(parts[2])
                        dur = hh * 3600 + mm * 60 + ss
                        if dur > 0:
                            return dur
            except Exception:
                pass

            return None

        try:
            fd, tmp_in = tempfile.mkstemp(suffix=".mp4")
            os.close(fd)
            with open(tmp_in, "wb") as f:
                f.write(video_bytes)

            dur = _get_duration_seconds(tmp_in)

            if dur is None:
                # If we can't determine duration, fall back near-start rather than failing
                seek = 0.2
            else:
                # 3 second before end, but clamp to sane bounds
                seek = dur - 3.0
                if seek < 0.2:
                    seek = 0.2
                # Also avoid seeking past end due to rounding/weird duration values
                if dur > 0.4 and seek > (dur - 0.2):
                    seek = max(0.2, dur - 0.2)

            # Fit inside box while preserving aspect ratio
            vf = f"scale='if(gte(iw,ih),{max_side},-2)':'if(gte(iw,ih),-2,{max_side})'"

            p = subprocess.run(
                [
                    "ffmpeg",
                    "-hide_banner",
                    "-loglevel", "error",
                    "-ss", str(seek),
                    "-i", tmp_in,
                    "-frames:v", "1",
                    "-vf", vf,
                    "-f", "image2",
                    "-vcodec", "mjpeg",
                    "pipe:1",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                check=False,
            )

            if p.returncode != 0 or not p.stdout:
                self.log.warning(
                    "ffmpeg thumbnail extract failed (seek=%s): %s",
                    seek,
                    (p.stderr or b"").decode("utf-8", "replace"),
                )
                return None

            jpeg = p.stdout
            dims = self._jpeg_dimensions(jpeg)
            if not dims:
                return (jpeg, max_side, max_side)
            w, h = dims
            return (jpeg, int(w), int(h))

        except Exception:
            self.log.exception("ffmpeg thumbnail extraction crashed")
            return None
        finally:
            if tmp_in:
                try:
                    os.remove(tmp_in)
                except Exception:
                    pass

    def _mk_thumb_from_image_any(self, data: bytes, max_side: int = 320, quality: int = 75) -> Optional[Tuple[bytes, int, int]]:
        """Make a JPEG thumbnail from any input image bytes (jpg/png/etc)."""
        if Image is None:
            return None
        try:
            im = Image.open(BytesIO(data))
            im = im.convert("RGB")
            im.thumbnail((max_side, max_side))
            w, h = im.size
            buf = BytesIO()
            im.save(buf, format="JPEG", quality=quality, optimize=True)
            return buf.getvalue(), int(w), int(h)
        except Exception:
            self.log.exception("Thumbnail creation from embedded CCTV image failed")
            return None


    def _mk_thumbnail_jpeg(self, data: bytes, max_side: int = 320, quality: int = 75) -> Optional[Tuple[bytes, int, int]]:
        """Create a JPEG thumbnail with Pillow; returns (thumb_bytes, w, h) or None."""
        if Image is None:
            return None
        try:
            im = Image.open(BytesIO(data))
            im = im.convert("RGB")
            im.thumbnail((max_side, max_side))
            w, h = im.size
            buf = BytesIO()
            im.save(buf, format="JPEG", quality=quality, optimize=True)
            return buf.getvalue(), int(w), int(h)
        except Exception:
            self.log.exception("Thumbnail creation failed")
            return None

    def _msgtype_for_mimetype(self, mimetype: str) -> str:
        mt = (mimetype or "").lower().strip()
        if mt.startswith("image/"):
            return "m.image"
        if mt.startswith("video/"):
            return "m.video"
        return "m.file"

    # ----------------------------
    # /send (TEXT)
    # ----------------------------

    @web.post("/send")
    async def send(self, request: Request) -> Response:
        self._check_auth(request)

        body, json_data = await self._read_body_and_json(request)
        ctx = self._ctx(request, body, json_data)

        room_tmpl = str(self.config.get("room", "") or "")
        msg_tmpl = str(self.config.get("message", "{{ body }}") or "")

        try:
            room = self._render(room_tmpl, ctx).strip()
        except jinja2.exceptions.UndefinedError as e:
            raise HTTPBadRequest(text=f"Room template error: {e}")

        if not room:
            raise HTTPBadRequest(text="room template rendered empty")

        try:
            msg = self._render(msg_tmpl, ctx)
        except jinja2.exceptions.UndefinedError as e:
            raise HTTPBadRequest(text=f"Message template error: {e}")

        if bool(self.config.get("ignore_empty_messages", False)) and not msg.strip():
            return Response(status=200)

        msgtype = str(self.config.get("message_type", "m.text") or "m.text").strip()
        fmt = str(self.config.get("message_format", "plaintext") or "plaintext").strip()

        content = self._build_text_content(msg, fmt, msgtype)

        await self._send_room_message(room, content)
        return Response(status=200)

    # ----------------------------
    # /send-image (IMAGE, E2EE attachment + optional encrypted thumbnail)
    # ----------------------------

    @web.post("/send-image")
    async def send_image(self, request: Request) -> Response:
        self._check_auth(request)

        max_bytes = int(self.config.get("max_upload_bytes", 5 * 1024 * 1024))
        content_type = (request.headers.get("Content-Type") or "").lower()

        room: str = ""
        caption: str = ""
        filename: str = "image.jpg"
        mimetype: str = "application/octet-stream"
        data: Optional[bytes] = None

        if content_type.startswith("multipart/form-data"):
            reader = await request.multipart()
            async for part in reader:
                name = part.name or ""
                if name == "room":
                    room = (await part.text()).strip()
                elif name in ("caption", "message"):
                    caption = (await part.text()).strip()
                elif name == "filename":
                    filename = (await part.text()).strip() or filename
                elif name == "mimetype":
                    mimetype = (await part.text()).strip() or mimetype
                elif name == "file":
                    if part.filename:
                        filename = part.filename
                    ct = part.headers.get(hdrs.CONTENT_TYPE)
                    if ct:
                        mimetype = ct
                    blob = await part.read()
                    if len(blob) > max_bytes:
                        raise HTTPBadRequest(text=f"File too large (>{max_bytes} bytes)")
                    data = blob
            ctx = self._ctx(request, body="", json_data=None)
        else:
            body, json_data = await self._read_body_and_json(request)
            ctx = self._ctx(request, body, json_data)

            if not bool(self.config.get("enable_base64_json", True)):
                raise HTTPBadRequest(text="JSON base64 mode disabled; use multipart/form-data")

            if not isinstance(json_data, dict):
                raise HTTPBadRequest(text="Expected JSON object body")

            room = str(json_data.get("room", "") or "").strip()
            caption = str(json_data.get("caption", json_data.get("message", "")) or "").strip()
            filename = str(json_data.get("filename", filename) or filename)
            mimetype = str(json_data.get("mimetype", "image/jpeg") or "image/jpeg")

            b64 = str(json_data.get("base64", "") or "").strip()
            if not b64:
                raise HTTPBadRequest(text="Missing 'base64' in JSON")

            try:
                data = base64.b64decode(b64, validate=True)
            except Exception:
                raise HTTPBadRequest(text="Invalid base64")

            if len(data) > max_bytes:
                raise HTTPBadRequest(text=f"File too large (>{max_bytes} bytes)")

        if not room:
            room = self._render(str(self.config.get("image_room", "") or ""), ctx).strip()
        if not room:
            raise HTTPBadRequest(text="Missing room (field 'room' or image_room template)")
        if data is None or len(data) == 0:
            raise HTTPBadRequest(text="Missing image data")

        if not caption:
            caption = self._render(str(self.config.get("image_caption", "") or ""), ctx).strip()
        if not caption:
            caption = filename or "image"

        dims = self._jpeg_dimensions(data)
        width: Optional[int] = None
        height: Optional[int] = None
        if dims:
            width, height = dims

        ciphertext, enc_file = encrypt_attachment([data])
        mxc = await self._upload_media_compat(ciphertext, "application/octet-stream", filename)

        try:
            enc_file.url = mxc
        except Exception:
            pass

        try:
            file_dict = enc_file.serialize()
        except Exception:
            file_dict = dict(enc_file) if isinstance(enc_file, dict) else {"url": str(mxc)}

        cap_fmt = str(self.config.get("image_caption_format", "plaintext") or "plaintext").strip().lower()

        content: Dict[str, Any] = {
            "msgtype": "m.image",
            "body": filename or "image.jpg",
            "file": file_dict,
            "info": {
                "mimetype": mimetype,
                "size": len(data),
            },
        }
        if width is not None and height is not None:
            content["info"]["w"] = width
            content["info"]["h"] = height

        if cap_fmt == "markdown":
            content["format"] = Format.HTML.value
            content["formatted_body"] = mx_markdown.render(caption)
        elif cap_fmt == "html":
            content["format"] = "org.matrix.custom.html"
            content["formatted_body"] = caption
        elif cap_fmt == "plaintext":
            pass
        else:
            raise HTTPBadRequest(text=f"Invalid image_caption_format: {cap_fmt}")

        thumb = self._mk_thumbnail_jpeg(data, max_side=320, quality=75)
        if thumb is not None:
            thumb_plain, tw, th = thumb
            try:
                thumb_cipher, thumb_enc_file = encrypt_attachment([thumb_plain])
                thumb_mxc = await self._upload_media_compat(thumb_cipher, "application/octet-stream", "thumb.jpg")
                try:
                    thumb_enc_file.url = thumb_mxc
                except Exception:
                    pass
                try:
                    thumb_file = thumb_enc_file.serialize()
                except Exception:
                    thumb_file = dict(thumb_enc_file) if isinstance(thumb_enc_file, dict) else {"url": str(thumb_mxc)}

                content["info"]["thumbnail_file"] = thumb_file
                content["info"]["thumbnail_info"] = {
                    "mimetype": "image/jpeg",
                    "size": len(thumb_plain),
                    "w": int(tw),
                    "h": int(th),
                }
            except Exception:
                self.log.exception("Failed to encrypt/upload thumbnail (continuing without thumbnail)")

        await self._send_room_message(room, content)
        return Response(status=200)

    # ----------------------------
    # /send-media (NEW: general media endpoint incl. video)
    # ----------------------------

    @web.post("/send-media")
    async def send_media(self, request: Request) -> Response:
        """
        Multipart:
          - room (required, or image_room template fallback)
          - caption/message (optional)
          - file (required)
          - filename (optional)
          - mimetype (optional; else from part content-type)

        JSON base64 mode also supported (enable_base64_json):
          { room, caption, filename, mimetype, base64 }
        """
        self._check_auth(request)

        max_bytes = int(self.config.get("max_upload_bytes", 5 * 1024 * 1024))
        content_type = (request.headers.get("Content-Type") or "").lower()

        room: str = ""
        caption: str = ""
        filename: str = "file.bin"
        mimetype: str = "application/octet-stream"
        data: Optional[bytes] = None

        if content_type.startswith("multipart/form-data"):
            reader = await request.multipart()
            async for part in reader:
                name = part.name or ""
                if name == "room":
                    room = (await part.text()).strip()
                elif name in ("caption", "message"):
                    caption = (await part.text()).strip()
                elif name == "filename":
                    filename = (await part.text()).strip() or filename
                elif name == "mimetype":
                    mimetype = (await part.text()).strip() or mimetype
                elif name == "file":
                    if part.filename:
                        filename = part.filename
                    ct = part.headers.get(hdrs.CONTENT_TYPE)
                    if ct:
                        mimetype = ct
                    blob = await part.read()
                    if len(blob) > max_bytes:
                        raise HTTPBadRequest(text=f"File too large (>{max_bytes} bytes)")
                    data = blob
            ctx = self._ctx(request, body="", json_data=None)
        else:
            body, json_data = await self._read_body_and_json(request)
            ctx = self._ctx(request, body, json_data)

            if not bool(self.config.get("enable_base64_json", True)):
                raise HTTPBadRequest(text="JSON base64 mode disabled; use multipart/form-data")
            if not isinstance(json_data, dict):
                raise HTTPBadRequest(text="Expected JSON object body")

            room = str(json_data.get("room", "") or "").strip()
            caption = str(json_data.get("caption", json_data.get("message", "")) or "").strip()
            filename = str(json_data.get("filename", filename) or filename)
            mimetype = str(json_data.get("mimetype", mimetype) or mimetype)

            b64 = str(json_data.get("base64", "") or "").strip()
            if not b64:
                raise HTTPBadRequest(text="Missing 'base64' in JSON")

            try:
                data = base64.b64decode(b64, validate=True)
            except Exception:
                raise HTTPBadRequest(text="Invalid base64")
            if len(data) > max_bytes:
                raise HTTPBadRequest(text=f"File too large (>{max_bytes} bytes)")

        if not room:
            room = self._render(str(self.config.get("image_room", "") or ""), ctx).strip()
        if not room:
            raise HTTPBadRequest(text="Missing room (field 'room' or image_room template)")
        if data is None or len(data) == 0:
            raise HTTPBadRequest(text="Missing file data")

        if not caption:
            caption = self._render(str(self.config.get("image_caption", "") or ""), ctx).strip()
        if not caption:
            caption = filename or "file"

        msgtype = self._msgtype_for_mimetype(mimetype)

        ciphertext, enc_file = encrypt_attachment([data])
        mxc = await self._upload_media_compat(ciphertext, "application/octet-stream", filename)

        try:
            enc_file.url = mxc
        except Exception:
            pass

        try:
            file_dict = enc_file.serialize()
        except Exception:
            file_dict = dict(enc_file) if isinstance(enc_file, dict) else {"url": str(mxc)}

        cap_fmt = str(self.config.get("image_caption_format", "plaintext") or "plaintext").strip().lower()

        content: Dict[str, Any] = {
            "msgtype": msgtype,
            "body": filename or "file",
            "file": file_dict,
            "info": {
                "mimetype": mimetype,
                "size": len(data),
            },
        }

        # Dimensions only for JPEG images
        if msgtype == "m.image":
            dims = self._jpeg_dimensions(data)
            if dims:
                w, h = dims
                content["info"]["w"] = int(w)
                content["info"]["h"] = int(h)

        if cap_fmt == "markdown":
            content["format"] = Format.HTML.value
            content["formatted_body"] = mx_markdown.render(caption)
        elif cap_fmt == "html":
            content["format"] = "org.matrix.custom.html"
            content["formatted_body"] = caption
        elif cap_fmt == "plaintext":
            pass
        else:
            raise HTTPBadRequest(text=f"Invalid image_caption_format: {cap_fmt}")

        # Optional thumbnail for images AND videos
        thumb: Optional[Tuple[bytes, int, int]] = None

        if msgtype == "m.image":
            # Thumb from actual image (Pillow)
            thumb = self._mk_thumbnail_jpeg(data, max_side=320, quality=75)

        elif msgtype == "m.video":
            # Thumb from first video frame (ffmpeg)
            thumb = self._mk_video_thumbnail_ffmpeg(data, max_side=320)
            if thumb is None:
                self.log.warning("No video thumbnail generated (ffmpeg_ok=%s)", FFMPEG_OK)

        if thumb is not None:
            thumb_plain, tw, th = thumb
            try:
                thumb_cipher, thumb_enc_file = encrypt_attachment([thumb_plain])
                thumb_mxc = await self._upload_media_compat(
                    thumb_cipher,
                    "application/octet-stream",
                    "thumb.jpg",
                )

                try:
                    thumb_enc_file.url = thumb_mxc
                except Exception:
                    pass

                try:
                    thumb_file = thumb_enc_file.serialize()
                except Exception:
                    thumb_file = dict(thumb_enc_file) if isinstance(thumb_enc_file, dict) else {"url": str(thumb_mxc)}

                content["info"]["thumbnail_file"] = thumb_file
                content["info"]["thumbnail_info"] = {
                    "mimetype": "image/jpeg",
                    "size": len(thumb_plain),
                    "w": int(tw),
                    "h": int(th),
                }
                self.log.info("Attached thumbnail for %s (%dx%d, %d bytes)", msgtype, tw, th, len(thumb_plain))
            except Exception:
                self.log.exception("Failed to encrypt/upload thumbnail (continuing without thumbnail)")



        await self._send_room_message(room, content)
        return Response(status=200)
