import webapp2

from user_methods import SignupHandler, LoginHandler, LogoutHandler
from wiki_methods import EditPage, WikiPage, HistoryPage

DEBUG = True #Change to false to upload
PAGE_RE = r'(/(?:[a-zA-Z0-9-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', SignupHandler), ('/login', LoginHandler), ('/logout', LogoutHandler), ('/_edit' + PAGE_RE, EditPage), (PAGE_RE, WikiPage), ('/_history' + PAGE_RE, HistoryPage)], debug=DEBUG)
