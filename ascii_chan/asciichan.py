import os
import webapp2
import jinja2
from xml.dom import minidom
import urllib2
import logging

from google.appengine.ext import db
from google.appengine.api import memcache

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
    
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"

IP_URL = "http://api.hostip.info/?ip="

def gmaps_img(points):
	markers = "&".join("markers=%s,%s" %(p.lat, p.lon) for p in points)
	return GMAPS_URL + markers

def get_coords(ip):
	ip="86.144.98.84"
	url = IP_URL + ip
	content = None
	
	try:
		content = urllib2.urlopen(url).read()
	except URLError:
		return
	
	if content:
		#parse url and get coords
		try:
			x = minidom.parseString(content)
		except:
			return "dom error"
		coords = x.getElementsByTagName("gml:coordinates")
		if coords.length > 0:
			lon, lat = coords[0].childNodes[0].nodeValue.split(",")
			return db.GeoPt(lat,lon)


def top_arts(update = False):
	key = "top"
	arts = memcache.get(key)
	if arts is None or update:
		logging.error("DB_QUERY")
		arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC LIMIT 10")
		
		arts = list(arts) #Otherwise query is executed each time we iterate over arts
		memcache.set(key, arts)
	
	return arts

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
		
	def render_str(self, template, **params):
		t = jinja_environment.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class Art(db.Model):
	title = db.StringProperty(required = True)
	art = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	coords = db.GeoPtProperty()

class MainPage(Handler):
	def render_front(self, title="", art="", error=""):
		arts = top_arts()
		
		#points =[]
		#for a in arts:
		#	if a.coords:
		#		points.append(a.coords)
		#Below is equivalent to above
		points = filter(None, (a.coords for a in arts))
		
		img_url = None
		if points:
			img_url = gmaps_img(points)
		
			
		self.render("front.html", title=title, art=art, error=error, arts=arts, img_url=img_url)
		
	def get(self):
		#self.write(self.request.remote_addr)
		
		self.render_front()
	
	def post(self):
		title = self.request.get("title")
		art = self.request.get("art")

		if title and art:
			a = Art(title = title, art = art)
			#Get users co-ordinates
			coords = get_coords(self.request.remote_addr)
			#If co-ordinates are returned add to art
			if coords:
				a.coords = coords
			a.put()
			#CACHE.clear()
			top_arts(True) #Prevents cache stampede by updatimg cache
			
			self.redirect("/")
		else:
			error = "We need both a title and some artwork!"
			self.render_front(title, art, error)
        
application = webapp2.WSGIApplication([('/', MainPage), ], debug=True)
