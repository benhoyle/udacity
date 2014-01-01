import os
import webapp2
import jinja2
#import json
import datetime
import re
import hashlib
import random
import string
import hmac
import logging
    
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
SECRET = "rup3VpAOr4Hj0DI"

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

def render_str(template, **params):
    t = jinja_environment.get_template(template)
    return t.render(params)

def valid_username(username):
	return USER_RE.match(username)
	
def valid_password(password):
    return PWD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

def verify_password(p1, p2):
	if p1 != p2:
		return None
	else:
		return p1

def make_salt():
	return ''.join([random.choice(string.ascii_letters) for n in xrange(5)])
	
def make_pw_hash(name, pw, salt=make_salt()):
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s|%s" % (h, salt)

def valid_pw(name, pw, h):
	salt = h.split('|')[1]
	return h == make_pw_hash(name, pw, salt)

def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()
	
def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))
	
def check_secure_val(h):
	val = h.split("|")[0]
	if h == make_secure_val(val):
		return val
