import json
import webapp2
import jinja2
from utils import *
import os
import logging
from google.appengine.ext import ndb

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
		
	def render_str(self, template, **params):
		#if user is logged in add to parameters to be rendered
		#Add code here to set login area options
		path = self.request.path
		params['url'] = path
		params['show_options'] = True
		if "_edit/" in path:
			params['show_options'] = None
			path = path.replace("_edit/","")
		if "_history/" in path:
			params['show_options'] = None
			path = path.replace("_history/","")
		if "?" in path:
			path = path.rsplit("?",1)[0]
		params['page_path'] = path
		params['user'] = self.user
		t = jinja_environment.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		if self.output_format == "html":
			self.write(self.render_str(template, **kw))
		if self.output_format == "json":
			self.render_json(kw)
	
	def set_secure_cookie(self, name, val=None):
		if val:
			cookie_val = make_secure_val(val)
		else:
			cookie_val = ""
		self.response.headers.add_header(
				'Set-Cookie','%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, userurlstring):
		self.set_secure_cookie('user_id', userurlstring)

	def logout(self):
		self.set_secure_cookie('user_id')
		
	def render_json(self, **kw):
	#Function to return json for rendering
	#Takes as input a list of objects
		json_list = []
		for o in objects:
			json_list.append(o.render_dict()) #do i need to import the o object?
		self.response.headers['Content-Type'] = 'application/json'
		#self.write(json.dumps(json_list))
		self.write(json_list)
		
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		self.user = None
		uid = self.read_secure_cookie('user_id')
		if uid:
			#logging.error("UID: " + uid)
			user_key = ndb.Key(urlsafe=uid)
			if user_key:
				#logging.error(user_key)
				self.user = user_key.get() #again do i need to import user
				#logging.error(self.user)
					
		if self.request.url.endswith('.json'):
			self.output_format = 'json'
		else:
			self.output_format = 'html'
