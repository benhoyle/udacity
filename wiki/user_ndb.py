from google.appengine.ext import ndb
from utils import *
import logging

class User(ndb.Model):
	username = ndb.StringProperty()
	password_hash = ndb.StringProperty()
	date_registered = ndb.DateTimeProperty(auto_now_add = True)
	email = ndb.StringProperty()
	
	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid)

	@classmethod
	def by_name(cls, name):
		u = cls.query().filter(cls.username == name).fetch()
		if len(u) > 0:
			#logging.error(u)
			return u.pop()
		else:
			return None
		
	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(username = name, password_hash = pw_hash, email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.password_hash):
			return u
