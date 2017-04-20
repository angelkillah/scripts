#!/usr/bin/env python2

"""
To run this application yourself, please install its requirements first:
	$ pip install -r requirements.txt
Then, you can actually run the application.
	$ ./run.py 
Afterwards, point your browser to http://localhost:5000
"""

from flask import Flask, render_template, flash
from flask_bootstrap import Bootstrap

UPLOAD_FOLDER = "tmp"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100mb max
app.secret_key = 'test'
Bootstrap(app)

import webui

if __name__ == "__main__":
    app.run(debug="True")
