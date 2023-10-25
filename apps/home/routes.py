# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.home import blueprint
from flask import render_template, request
from flask_login import login_required
from jinja2 import TemplateNotFound


@blueprint.route('/index')
@login_required
def index():

    return render_template('home/index.html', segment='index')

# @blueprint.route('/explore')
# def explore():
#     return render_template('home/explore.html', segment='explore')

@blueprint.route('/parcelservice')
def parcelservice():
    return render_template('home/parce-transport.html', segment='parcelservice')

@blueprint.route('/soloservice')
def soloservice():
    return render_template('home/solo-travel.html', segment='soloservice')

@blueprint.route('/studentservice')
def studentservice():
    return render_template('home/student-travel.html', segment='studentservice')

@blueprint.route('/eventservice')
def eventservice():
    return render_template('home/event-travel.html', segment='eventservice')

# @blueprint.route('/profile')
# def profile():
#     return render_template('home/profile.html', segment='profile')



@blueprint.route('/<template>')
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
