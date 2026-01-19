# maubot-webhook
A [maubot](https://github.com/maubot/maubot) plugin to send messages using webhooks.

This fork adds **encrypted (E2EE-safe) media uploads** and additional endpoints for images and general media.

## Features
- Jinja2 templating (StrictUndefined)
- JSON support (optional forced JSON parsing)
- HTTP Basic and Bearer token authorization
- **Text endpoint**: POST /send
- **Image endpoint**: POST /send-image (encrypted Matrix attachments, optional encrypted thumbnail)
- **Media endpoint**: POST /send-media (image/video/file; encrypted attachments, optional thumbnails for images and videos)
- Best-effort optional dependencies:
  - Pillow for image thumbnails (tries to install via pip if missing)
  - ffmpeg for video thumbnails (tries to install via apk if missing)

## Installation
Either download an `.mbp` file from the release assets (if available) or build one yourself.
Then upload it to your maubot instance.

This plugin uses Jinja2 for template rendering. Since maubot already depends on Jinja2, you usually don’t need to install it manually.

## Usage
Create a new instance in the maubot management interface and select
`me.jkhsjdhjs.maubot.webhook` as Type.

The client selected as Primary user will be used to send messages.

Each instance of this plugin provides these endpoints:

- POST /send (text)
- POST /send-image (image)
- POST /send-media (general media)

They are available under:

https://your.maubot.instance/_matrix/maubot/plugin/\<instance_id\>/\<endpoint\>

To create multiple webhooks, instantiate this plugin multiple times.

## Example (text /send)

Example configuration:
```yaml
room: "!AAAAAAAAAAAAAAAAAA:example.com"  
message: |  
  **{{ json.title }}**  
  {% for text in json.list %}  
  - {{ text }}  
  {% endfor %}  
message_format: markdown  
message_type: m.text  
auth_type: Bearer  
auth_token: supersecrettoken  
force_json: false  
ignore_empty_messages: false  
```
Example request:
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer \<token\>" \
  "https://your.maubot.instance/_matrix/maubot/plugin/\<instance_id\>/send" \
  -d '{
    "title": "This is a test message:",
    "list": ["Hello", "World!"]
  }'
```
## Configuration (text)

- room: target room ID (templated)
- message: message template (templated)
- message_format: plaintext | markdown | html
- message_type: m.text | m.notice
- auth_type: "" | Basic | Bearer
- auth_token:
  - Basic: \<username\>:\<password\>
  - Bearer: \<token\>
- force_json: true | false
- ignore_empty_messages: true | false

## Image endpoint: /send-image

Uploads an image to the Matrix media repository and sends an m.image message.
Uploads are sent as encrypted Matrix attachments (E2EE-safe).

Relevant configuration:
- image_room: fallback room template
- image_caption: fallback caption template
- image_caption_format: plaintext | markdown | html
- max_upload_bytes: upload limit in bytes
- enable_base64_json: true | false

Multipart request fields:
- room (required unless image_room is set)
- file (required)
- caption or message (optional)
- mimetype (optional)
- filename (optional)

Example:
```bash
curl -X POST \
  -H "Authorization: Bearer \<token\>" \
  -F "room=!roomid:server" \
  -F "caption=Snapshot" \
  -F "file=@snapshot.jpg;type=image/jpeg" \
  "https://your.maubot.instance/_matrix/maubot/plugin/\<instance_id\>/send-image"
```
JSON base64 mode example:
```yaml
{
  "room": "!roomid:server",
  "caption": "Snapshot",
  "filename": "snapshot.jpg",
  "mimetype": "image/jpeg",
  "base64": "\<base64 bytes\>"
}
```
## Media endpoint: /send-media

General media endpoint for images, videos, and files.
Sends m.image, m.video, or m.file depending on mimetype.
Uploads are encrypted Matrix attachments (E2EE-safe).

Uses the same configuration as /send-image.

Multipart fields:
- room
- file
- caption or message
- mimetype
- filename

Example (video):
```bash
curl -X POST \
  -H "Authorization: Bearer \<token\>" \
  -F "room=!roomid:server" \
  -F "caption=Clip" \
  -F "file=@clip.mp4;type=video/mp4" \
  "https://your.maubot.instance/_matrix/maubot/plugin/\<instance_id\>/send-media"
```
## Thumbnails
- Images: generated using Pillow (optional)
- Videos: generated using ffmpeg (optional)

If unavailable, uploads still succeed without thumbnails.

Note: Increase max_upload_bytes when sending videos.

## Formatting
The room, message, image_room, and image_caption options support Jinja2 templates.

Available variables:
- path: URL path parameters
- query: query parameters
- headers: request headers
- body: raw request body
- json: parsed JSON body (if applicable)

## Escaping
HTML escaping is enabled automatically.
To disable escaping for a value, use the safe filter:

{{ foo | safe }}

Markdown is NOT auto-escaped. Use:

{{ foo | escape_md }}

## Building
```bash
mbc build
mbc build -u
```
Alternatively, zip the repository:
```bash
zip -9r webhook.mbp *
```
## License
GNU Affero General Public License v3.0
