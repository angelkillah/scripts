from flask import render_template, request, redirect, url_for, flash
from werkzeug import secure_filename
import random, string
from metaPE import app
import os

from Core import Core

core = Core()
UPLOAD_FOLDER = "/tmp/metaPE/"

@app.route('/', methods = ('GET', 'POST'))
def index():
	result = 0

	if request.method.lower() == 'get':	
		""" here we want to pass all the unique tags names in parameter """
		tags = []
		list_tags = core.wrap_get_all_unique_tags()
		for tag in list_tags:
			tags.append(tag[0])		
		return render_template('index.html', option_list=tags)

	elif request.method.lower() == 'post':
		if 'file' not in request.files:
			flash('File is missing')
			return redirect(request.url)
		
		f = request.files['file']
		if f.filename == "":
			flash('File is missing', 'error')
			return redirect(request.url)
			
		random_name = "".join(random.choice(string.ascii_lowercase) for x in range(10))
		f.save("/tmp/" + random_name)

		add_to_db = request.form.getlist('add_to_db')
		check_simil = request.form.getlist('check_simil')
		if request.form.getlist('tag')[0]:
			tag = request.form.getlist('tag')[0]
		else:
			tag = request.form['new_tag']

		if add_to_db and tag:
			msg = core.wrap_store_to_db("/tmp/" + random_name, tag)	
			flash(msg, 'error')

		if check_simil:
			res = core.check_similarities("/tmp/" + random_name)
			if not res:
				flash('[-] No common rich header info :(', 'error')
			else:
				print res
				return render_template('result.html', result=res)
			
		if check_simil or (add_to_db and tag):
			return redirect(url_for("index"))

		flash('Missing field', 'error')
		return redirect(url_for("index"))

@app.route('/search', methods = ('GET', 'POST'))
def search():
	data = core.wrap_dump_db()
	return render_template('search.html', data=data)