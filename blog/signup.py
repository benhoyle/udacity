import re, hashlib, random, string

from google.appengine.ext import ndb

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

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
	salt = h.split('|')[0]
	return h == make_pw_hash(name, pw, salt)

class User(ndb.Model):
	username = ndb.StringProperty()
	password = ndb.StringProperty()
	date_registered = ndb.DateTimeProperty(auto_now_add = True)
	email = ndb.StringProperty()

