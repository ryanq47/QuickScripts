from flask import Flask, render_template_string, request, Response, send_file
import os
import mimetypes
import zipfile
from io import BytesIO

PASSWORD = "hosted"

app = Flask(__name__)

def zip_dir(path, buffer, password):
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                # Add file to zip and set a password
                zipf.write(file_path, os.path.relpath(file_path, start=path))
        # Set the password for the ZIP file
        zipf.setpassword(password.encode())

def render_directory(path):
    abs_path = os.path.join(os.getcwd(), path)
    items = os.listdir(abs_path)
    links = []
    for item in items:
        item_path = os.path.join(abs_path, item)
        size = os.path.getsize(item_path)
        if os.path.isdir(item_path):
            links.append(f'<a href="{os.path.join(request.path, item)}" style="text-decoration: underline;">{item}/</a><span style="float: right;">{size} bytes</span><br>')
        else:
            links.append(f'<a href="{os.path.join(request.path, item)}" style="text-decoration: none;">{item}</a><span style="float: right;">{size} bytes</span><br>')
    download_button = f'''
    <form action="{request.path}" method="get">
        <input type="hidden" name="download" value="1">
        <button type="submit">Download this directory</button>
    </form>
    '''
    parent_dir = os.path.dirname(request.path.rstrip('/'))
    parent_link = f'<a href="{parent_dir}">.. (Parent Directory)</a><br>' if parent_dir else ''
    links_html = parent_link + download_button + "<br>" + "".join(links)
    style = """
    <style>
        body { background-color: #121212; color: #33ff33; font-family: 'Courier New', Courier, monospace; }
        a { color: #33ff33; }
        a:hover { color: #ffffff; }
        button { background-color: #444444; color: #33ff33; border: none; padding: 10px 15px; border-radius: 5px; cursor: pointer; }
        button:hover { background-color: #555555; }
        form { margin-top: 20px; }
        span { display: inline-block; width: 100%; text-align: right; color: #888; }
    </style>
    """
    custom_message = f"<p>Please navigate through the directories or click on files to view them. Use the links to move through the directory structure or download the entire directory. Password for zip files is: {PASSWORD}</p>"
    return render_template_string(style + f"<h1>Directory Listing for {path}</h1>{custom_message}<p>{links_html}</p>")

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_file(path):
    abs_path = os.path.join(os.getcwd(), path)
    if request.args.get('download') and os.path.isdir(abs_path):
        memory_file = BytesIO()
        # Define a simple password
        password = PASSWORD
        zip_dir(abs_path, memory_file, password)
        memory_file.seek(0)
        return send_file(memory_file, download_name=f"{os.path.basename(path)}.zip", as_attachment=True)

    if os.path.isdir(abs_path):
        return render_directory(path)
    elif os.path.isfile(abs_path):
        mime_type, _ = mimetypes.guess_type(abs_path)
        mime_type = mime_type or 'application/octet-stream'
        with open(abs_path, 'rb') as file:
            file_content = file.read()
        return Response(file_content, mimetype=mime_type)
    else:
        return "File not found", 404

if __name__ == "__main__":
    app.run(debug=True, port=5000)
