from google.appengine.ext import ndb
import logging
from utils import *

class Url(ndb.Model):
	url = ndb.StringProperty(required = True)
	
	@classmethod
	def get_url(cls, url_string):
		u = cls.query().filter(cls.url == url_string).fetch()
		if len(u) > 0:
			return u.pop()
		else:
			return None

class Wiki(ndb.Model):
	#Has url as parent key
	content = ndb.TextProperty(required = True)
	created = ndb.DateTimeProperty(auto_now_add = True)
	#last_modified = db.DateTimeProperty(auto_now = True)
	userkey = ndb.IntegerProperty(required = True)
	
	def render_text(self):
		return self.content.replace('\n', '<br>')
		
	def render_dict(self):
		page_dict = {}
		#page_dict['url'] = self.url
		page_dict['content'] = self.content
		page_dict['created'] = self.created.strftime("%c")
		#page_dict['last_modified'] = self.last_modified.strftime("%c")
		return page_dict
	
	@classmethod
	def by_id(cls, uid):
		#If i was doing this properly would have wiki and user both derived from an abstract class to share this method
		return cls.get_by_id(uid)
	
	@classmethod
	def get_wiki(cls, url):
		ancestor = Url.get_url(url)
		#logging.error(ancestor)
		if ancestor:
			#Query for all wiki objects associated with a URL, ordered by date
			c = cls.query(ancestor=ancestor.key).order(-cls.created).fetch(1)
			if len(c) > 0:
				return c.pop()
			else:
				return None
		else:
			return None
			
	@classmethod
	def get_history(cls, url):
		ancestor = Url.get_url(url)
		#logging.error(ancestor)
		if ancestor:
			#Query for all wiki objects associated with a URL, ordered by date
			c = cls.query(ancestor=ancestor.key).order(-cls.created).fetch()
			if len(c) > 0:
				return c
			else:
				return []
		else:
			return []
