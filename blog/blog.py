import os
import webapp2
import jinja2
import json
import datetime
import re, hashlib, random, string, hmac
import logging, time

from google.appengine.ext import ndb
from google.appengine.api import memcache

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

def render_str(template, **params):
    t = jinja_environment.get_template(template)
    return t.render(params)
    
##USER STUFF

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
	qry = User.query(User.username == username)
	user = qry.get()
	if not user:
		return USER_RE.match(username)
	else:
		return None
    
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

SECRET = "rup3VpAOr4Hj0DI"

def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()
	
def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))
	
def check_secure_val(h):
	val = h.split("|")[0]
	if h == make_secure_val(val):
		return val

class User(ndb.Model):
	username = ndb.StringProperty()
	password = ndb.StringProperty()
	date_registered = ndb.DateTimeProperty(auto_now_add = True)
	email = ndb.StringProperty()

##HANDLER STUFF

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
		
	def render_str(self, template, **params):
		t = jinja_environment.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		if self.output_format == "html":
			self.write(self.render_str(template, **kw))
		if self.output_format == "json":
			objects = kw['blogposts']
			self.render_json(objects)
		
	def set_cookie(self, user_key=None):
		if user_key:
			urlString = user_key.urlsafe()
			
			#store cookie identifying user
			h2 = make_secure_val(urlString)
		else:
			h2 = ""
		self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % h2)
		
	def render_json(self, objects):
	#Function to return json for rendering
	#Takes as input a list of objects
		json_list = []
		for o in objects:
			json_list.append(o.render_dict())
		self.response.headers['Content-Type'] = 'application/json'
		#self.write(json.dumps(json_list))
		self.write(json_list)
		
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		#uid = self.read_secure_cookie('user_id')
		#self.user = uid and User.by_id(int(uid))
		if self.request.url.endswith('.json'):
			self.output_format = 'json'
		else:
			self.output_format = 'html'

class BlogPost(ndb.Model):
	subject = ndb.StringProperty(required = True)
	content = ndb.TextProperty(required = True)
	created = ndb.DateTimeProperty(auto_now_add = True)
	
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", blogpost = self)
		
	def render_dict(self):
		blog_dict = {}
		blog_dict['subject'] = self.subject
		blog_dict['content'] = self.content
		created = self.created
		blog_dict['created'] = created.strftime("%c")
		return blog_dict

def top_posts(update = False):
	key = "top"
	blogposts = memcache.get(key)
	if blogposts is None or update:
		logging.error("DB_QUERY")
		blogposts = ndb.gql("SELECT * FROM BlogPost ORDER BY created DESC LIMIT 15")
		blogposts = list(blogposts)
		memcache.set(key, blogposts)
		memcache.set("query_time", time.time())
	return blogposts

class MainPage(Handler):	
	def get(self):
		blogposts = top_posts()
		
		last_query = memcache.get("query_time")
		if last_query is not None:
			seconds = round((time.time() - last_query),2)
		else:
			seconds = 0
		query_time = "Queried " + str(seconds) + " seconds ago"
		
		self.render("front2.html", blogposts=blogposts, query_time=query_time)

class NewPost(Handler):
	#Request Handler for Adding a New Blog Post
	def render_form(self, subject="", content="", error=""):
		self.render("newblog.html", subject=subject, content=content, error=error)
	
	def get(self, subject="", content=""):
		self.render_form()
	
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			b = BlogPost(subject = subject, content = content)
			b.put()
			key = b.key.id()
			time.sleep(0.5)
			top_posts(True)
			self.redirect("/%s" % str(key))
			#Need to redirect to permalink here
		else:
			error = "Please provide both a subject and some content!"
			self.render_form(subject, content, error)

def cached_post(key):
	blogpost = memcache.get(key)
	if blogpost is None:
		logging.error("DB_QUERY")
		blogpost = BlogPost.get_by_id(int(key))
		memcache.set(key, blogpost)
		memcache.set(key + "qt", time.time())
	return blogpost

class PostViewer(Handler):	
	def get(self, post_id):
		#blog = BlogPost.get_by_id(int(post_id))
		blog = cached_post(post_id)
		if not blog: 
			self.error(404)
			return
		last_query = memcache.get(post_id + "qt")
		if last_query is not None:
			seconds = round((time.time() - last_query),2)
		else:
			seconds = 0
		query_time = "Queried " + str(seconds) + " seconds ago"
		
		self.render("front2.html", blogposts=[blog], query_time=query_time)


class SignUpHandler(Handler):
	def get(self):
		self.render('signup.html')
		
	def post(self):
		error = False
		username = self.request.get('username')
		p1 = self.request.get('password')
		p2 = self.request.get('verify')
		email = self.request.get('email')
		un_check = valid_username(username)
		pw_check = valid_password(p1)
		verify_check = verify_password(p1,p2)
		params = dict(username = username, email = email)
		
		#Only validate email if entered
		if email != "":
			email_check = valid_email(email)
		else:
			email_check = "Not needed"
		
		if un_check == None:
			params['username_error'] = "Username not valid, please enter another"
			error = True
			
		if pw_check == None:
			params['password_error'] = "Please enter a valid password"
			error = True
			
		if verify_check == None:
			params['verify_error'] = "Passwords do not match"
			error = True
		
		if email_check == None:
			params['email_error'] = "Please enter a valid email"
			error = True
		
		if error == True:
			
			self.render('signup.html', 	**params)
		else:
			#Generate a hashed password string
			h = make_pw_hash(username, p1)
			
			#Create a new user
			u = User(username = username, password = h, email = email)
			user_key = u.put()
			self.set_cookie(user_key)
			
			self.redirect('/welcome')
			
class WelcomeHandler(Handler):
	def get(self):
		registered = False
		h2 = self.request.cookies.get('user')
		if h2:
			key = check_secure_val(h2)
			if key:
				user_key = ndb.Key(urlsafe=key)
				
				if user_key:
					registered = True
					user = user_key.get()
			
		if registered == True:
				self.write('Welcome, ' + user.username + '!')
		else:
			self.redirect('/signup')

class LoginHandler(Handler):
	def get(self):
		self.render('login.html')
	
	def post(self):
		valid_login = False
		username = self.request.get('username')
		password = self.request.get('password')
		
		#retrieve user object that matches username
		qry = User.query(User.username == username)
		user = qry.get()
				
		if user:
						
			if valid_pw(username, password, user.password):
				valid_login = True
		
		if valid_login:
			self.set_cookie(user.key)
			self.redirect('/welcome')
		else:
			params = dict(login_error = "Invalid Login")
			self.render('login.html', **params)
		
class LogoutHandler(Handler):
	def get(self):
		self.set_cookie()
		self.redirect('/signup')
		
class FlushHandler(Handler):
	def get(self):
		memcache.flush_all()
		self.redirect('/')
        
application = webapp2.WSGIApplication([('/?(?:\.json)?', MainPage), 
	('/newpost', NewPost), 
	('/(\d+)(?:.json)?', PostViewer), 
	('/signup', SignUpHandler), 
	('/welcome', WelcomeHandler), 
	('/login', LoginHandler), 
	('/logout', LogoutHandler), 
	('/flush', FlushHandler)], debug=True)
