from handler import Handler
from user_ndb import User
#Need to import datamodels?
from utils import *

class SignupHandler(Handler):
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
		
		if un_check is None or User.by_name(username) is not None :
			params['username_error'] = "Username not valid, please enter another"
			error = True
			
		if pw_check is None:
			params['password_error'] = "Please enter a valid password"
			error = True
			
		if verify_check is None:
			params['verify_error'] = "Passwords do not match"
			error = True
		
		if email_check is None:
			params['email_error'] = "Please enter a valid email"
			error = True
		
		if error:
			self.render('signup.html', 	**params)
		else:
			#Create a new user
			u = User.register(username, p1, email)
			user_key = u.put()
			self.login(user_key.urlsafe())
			
			self.redirect('/')

class LoginHandler(Handler):
	def get(self):
		self.render('login.html')
	
	def post(self):
		valid_login = False
		username = self.request.get('username')
		password = self.request.get('password')
		
		#retrieve user object that matches username
		#qry = User.query(User.username == username)
		#user = qry.get()
		user = User.login(username, password)
		if user:
			self.login(user.key.urlsafe())
			self.redirect('/')
		else:
			params = dict(login_error = "Invalid Login")
			self.render('login.html', **params)
		
class LogoutHandler(Handler):
	def get(self):
		self.logout()
		#encode current url as get parameter - use to redirect
		path = self.request.get('path')
		#self.write(path)
		self.redirect(path)
