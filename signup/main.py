import os
import webapp2
import jinja2
import re, hashlib, random, string, hmac

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(template_dir))

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
	
	#def return_user(cls, username):
		#return cls.query(User.username == username)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
		
	def render_str(self, template, **params):
		t = jinja_environment.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
		
	def set_cookie(self, user_key=None):
		if user_key:
			urlString = user_key.urlsafe()
			
			#store cookie identifying user
			h2 = make_secure_val(urlString)
		else:
			h2 = ""
		self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % h2)

class MainPage(Handler):
	def get(self):
		pass	

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
        
application = webapp2.WSGIApplication([('/', MainPage), ('/signup', SignUpHandler), ('/welcome', WelcomeHandler), ('/login', LoginHandler), ('/logout', LogoutHandler)], debug=True)
