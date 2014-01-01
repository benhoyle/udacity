from handler import Handler
from wikipage_ndb import Url, Wiki
import logging
from google.appengine.ext import ndb


class EditPage(Handler):
	def create_wiki(self, url_object, content):
		#create new wiki object 
		wiki = Wiki(parent=url_object.key, content=content, userkey=self.user.key.id())
		wiki.put()

	def get(self, url):
		if self.user:
			edit_id = self.request.get('e')
			if edit_id is not "":
				wiki_key = ndb.Key(urlsafe=edit_id)
				if wiki_key:
					#render edit page with textarea contents equal to store content
					self.render("edit.html", content = wiki_key.get().content)
					return
			else:
				#Load content for that url
				wiki = Wiki.get_wiki(url)
				if wiki:
					#render edit page with textarea contents equal to store content
					self.render("edit.html", content = wiki.content)
					#logging.error("Found wiki")
				else:
					#render blank edit page
					self.render("edit.html", content = "")
		else:
			#logging.error("No user")
			self.redirect(url)
	
	def post(self, url):
		content = self.request.get("content")
		url_object = Url.get_url(url)
		if url_object is None:
			#if url does not exist create a new url object and a new wiki object
			url_object = Url(url=url)
			url_object.put()
		self.create_wiki(url_object, content)
		#logging.error(url)
		self.redirect(url)
	
	
class WikiPage(Handler):
	def get(self, url):
		url = str(url)
		
		wiki = Wiki.get_wiki(url)
		if wiki:
			logging.error("Wikipage: Wiki found")
			logging.error(wiki)
			self.render("wikipage.html", wiki=wiki)
		else:
			if self.request.path == "/":
					self.render("frontpage.html", content = "Virgin Wiki - Edit Me!")
			else:
				if self.user:
					logging.error(url)
					self.redirect("/_edit" + url) #doesn't work on root
				else:
					self.redirect("/")
			
class HistoryPage(Handler):
	def get(self, url):
		view_id = self.request.get('v')
		if view_id is not "":
			#wiki = Wiki.get_by_id(int(view_id)) #didnt work for some reason
			wiki_key = ndb.Key(urlsafe=view_id)
			if wiki_key:
				self.render("wikipage.html", wiki=wiki_key.get())
				return
		edit_id = self.request.get('e')
		if edit_id is not "":
			wiki_key = ndb.Key(urlsafe=edit_id)
			if wiki_key:
				#render edit page with textarea contents equal to store content
				self.render("edit.html", content = wiki_key.get().content)
				return
		url = str(url)
		wikis = Wiki.get_history(url)
		if len(wikis) > 0:
			self.render("history.html", wikis = wikis)
		else:
			self.redirect("/")
