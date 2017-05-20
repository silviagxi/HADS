#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
from webapp2_extras import sessions
import session_module
from google.appengine.ext import ndb
import cgi
import re

REGISTRO_HTML = """<html> <head> <title>Introduzca sus datos:</title> <style
type="text/css"> .label {text-align: right} .error {color: red} </style>
<link rel="STYLESHEET" type="text/css" href="Sedna/css/styles.css"/>
</head> <body> <h1>Registro</h1> <h2>Rellene los campos por
favor:</h2> <form method="post"> <table> <tr> <td
class="label"> Nombre de usuario </td> <td> <input
type="text" name="username" value="%(username)s" placeholder="Tu nombre
..."> </td> <td class="error"> %(username_error)s
</td> </tr> <tr> <td class="label"> Password
</td> <td> <input type="password" name="password"
value="%(password)s" autocomplete="off"> </td> <td
class="error"> %(password_error)s </td> </td>
</tr> <tr> <td class="label"> Repetir Password </td>
<td> <input type="password" name="verify" value="%(verify)s"
placeholder="El mismo de antes"> </td> <td class="error">
%(verify_error)s </td> </tr> <tr> <td class="label">
Email </td> <td> <input type="text" name="email"
value="%(email)s"> </td> <td class="error">
%(email_error)s </td> </tr> </table> <input
type="submit"> <a href="/">Atras</a></form> </body> </html>
"""

INICIO_HTML = """<html><head><link rel="STYLESHEET" type="text/css" href="Sedna/css/styles.css"/>
<title>QUIZ</title> <h1>QUIZ.. preguntas y mucho mas</h1></head>
<body><h4>Si quieres anadir o ver preguntas super interesantes..</h4>
<form method="post"> <table> 
<tr> <td class="label"> Email </td> <td> <input type="text" name="email" value="%(email)s"> </td></tr> 
<tr> <td class="label">Password</td><td> <input type="password" name="password" value="%(password)s" autocomplete="off"></td></tr>
</table><input type="submit">
<h5>Si todavia no te has registrado, hazlo <a href="/registro">aqui</a></h5>
</body></html>
"""
WELCOME_HTML = """<html><head><link rel="STYLESHEET" type="text/css" href="Sedna/css/styles.css"/>
<title>QUIZ</title> <h2>Bienvenido %(mail)s</h2><a href="/logout">Log out</a></head>
<body><h3><a href="/anadir">Anadir preguntas</a></h3><h3><a href="/ver">Ver preguntas</a></h3>
</body></html>"""

ANADIR_HTML = """<html> <head> <title>Anadir preguntas:</title> <style
type="text/css"> .label {text-align: right} .error {color: red} </style>
<link rel="STYLESHEET" type="text/css" href="Sedna/css/styles.css"/>
</head> <body> <h2>Anadir preguntas</h2> <h5>Rellene los campos por
favor:</h5> <form method="post"> <table> <tr> <td
class="label">Enunciado pregunta</td> <td> <input
type="text" name="enunciado" value="%(enunciado)s" placeholder=" 2+2
..."> </td> <td class="error"> %(enunciado_error)s
</td> </tr> <tr> <td class="label"> Respuesta 1
</td> <td> <input type="resp1" name="resp1"
value="%(resp1)s" placeholder="4"> </td> <td
class="error"> %(resp1_error)s </td> </td>
</tr><tr> <td class="label">Respuesta 2</td> <td> <input
type="text" name="resp2" value="%(resp2)s" placeholder="3"> 
</td> <td class="error"> %(resp2_error)s
</td> </tr><tr> <td class="label">Respuesta 3</td> <td> <input
type="text" name="resp3" value="%(resp3)s" placeholder="5"> 
</td> <td class="error"> %(resp3_error)s
</td> </tr> <tr> <td class="label">
Numero de la respuesta correcta </td> <td> <input type="text" name="numcorrec"
value="%(numcorrec)s" placeholder="1"> </td> <td class="error">
%(numcorrec_error)s </td> </tr> <tr> <td class="label">
Tema </td> <td> <input type="text" name="tema"
value="%(tema)s" placeholder="Matematicas"> </td> <td class="error">
%(tema_error)s </td> </tr> </table> <input
type="submit"> <a href="/welcome">Atras</a></form> </body> </html>
"""

VER_HTML = """<html> <head> <title>Anadir preguntas:</title> <style
type="text/css"> .label {text-align: right} .error {color: red} </style>
<link rel="STYLESHEET" type="text/css" href="Sedna/css/styles.css"/>
</head> <body> <h2>Ver preguntas</h2> <a href="/welcome">Atras</a><h5>Aqui podras ver todas las preguntas</h5></body>"""

class Visitante(ndb.Model):
	username=ndb.StringProperty()
	email=ndb.StringProperty()
	password=ndb.StringProperty()
	
class Pregunta(ndb.Model):
	enunciado=ndb.StringProperty()
	resp1=ndb.StringProperty()
	resp2=ndb.StringProperty()
	resp3=ndb.StringProperty()
	numcorrec=ndb.StringProperty()
	tema=ndb.StringProperty()
	
class Registro(session_module.BaseSessionHandler):
	def write_form (self, username="", password="", verify="",
					email="", username_error="", password_error="",
					verify_error="", email_error=""):
		self.response.out.write(REGISTRO_HTML % {"username" :
		username,"password" : password,
		"verify" : verify,"email" : email,
		"username_error" : username_error,
		"password_error" : password_error,
		"verify_error" : verify_error,
		"email_error" : email_error})
	def get(self):
		self.write_form()
	def post(self):
		def escape_html(s):
			return cgi.escape(s, quote=True)
		def valid_username(username):
			return USER_RE.match(username)
		def valid_password(password):
			return PASSWORD_RE.match(password)
		def valid_email(email):
			return EMAIL_RE.match(email)
		USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		PASSWORD_RE = re.compile(r"^.{3,20}$")
		EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
		user_username = self.request.get('username')
		user_password = self.request.get('password')
		user_verify = self.request.get('verify')
		user_email = self.request.get('email')
		sani_username = escape_html(user_username)
		sani_password = escape_html(user_password)
		sani_verify = escape_html(user_verify)
		sani_email = escape_html(user_email)
		username_error = ""
		password_error = ""
		verify_error = ""
		email_error = ""
		error = False
		if not valid_username(user_username):
			username_error = "Nombre incorrecto!"
			error = True
		if not valid_password(user_password):
			password_error = "Password incorrecto!"
			error = True
		if not user_verify or not user_password == user_verify:
			verify_error = "Password no coincide!"
			error = True
		if not valid_email(user_email):
			email_error = "Email incorrecto!"
			error = True
		if error:
			self.write_form(sani_username, sani_password, sani_verify, sani_email,
			username_error, password_error, verify_error, email_error)
		else:
			user= Visitante.query(ndb.OR(Visitante.username==user_username, 
			Visitante.email==user_email)).count()
			
			if user==0:
				u=Visitante()
				u.username=user_username
				u.email=user_email
				u.password=user_password
				u.put()
				self.session['usuario'] = user_email
				self.redirect("/welcome")
			else:
				self.write_form(sani_username, sani_password, sani_verify, sani_email,
				username_error, password_error, verify_error, email_error)
				self.response.out.write ("%s ya estas registrado "%user_username)

class Inicio(session_module.BaseSessionHandler):
	def write_form (self, email="", password=""):
		self.response.write(INICIO_HTML % {"email" : email,"password" : password})
	def get(self):
		self.write_form()
	def post(self):
		def escape_html(s):
			return cgi.escape(s, quote=True)
		user_email=self.request.get("email")
		user_password = self.request.get("password")
		user= Visitante.query(Visitante.email==user_email, Visitante.password==user_password).count()
		if user==0:
			self.write_form()
			self.response.out.write("<p>Usuario o contrasena incorrectos, intentalo de nuevo</p>")	
		else:
			self.session['usuario'] = user_email
			self.redirect("/welcome")		

class Welcome(session_module.BaseSessionHandler):
	def get(self):
		if self.session.get('usuario'):
			self.response.write(WELCOME_HTML % {"mail" : self.session.get('usuario')})
		else:
			self.redirect('/')

class Anadir(session_module.BaseSessionHandler):
	def write_form (self, enunciado="", enunciado_error="", resp1="", resp1_error="", resp2="", resp2_error="",
					resp3="",resp3_error="", numcorrec="", numcorrec_error="", tema="", tema_error=""):
		self.response.out.write(ANADIR_HTML % {"enunciado":enunciado, "enunciado_error" : enunciado_error,
		"resp1" : resp1, "resp1_error" : resp1_error,
		"resp2" : resp2, "resp2_error" : resp2_error,
		"resp3" : resp3, "resp3_error" : resp3_error,
		"numcorrec" : numcorrec, "numcorrec_error" : numcorrec_error,
		"tema" : tema, "tema_error" : tema_error})
	def get(self):
		if self.session.get('usuario'):
			self.write_form()
		else:
			self.redirect('/')
	def post(self):
		def escape_html(s):
			return cgi.escape(s, quote=True)
		def valid_enunciado(enunciado):
			return ERT_RE.match(enunciado)
		def valid_resp1(resp1):
			return ERT_RE.match(resp1)
		def valid_resp2(resp2):
			return ERT_RE.match(resp2)
		def valid_resp3(resp3):
			return ERT_RE.match(resp3)
		def valid_numcorrec(numcorrec):
			return NUMCORREC_RE.match(numcorrec)
		def valid_tema(tema):
			return ERT_RE.match(tema)
		ERT_RE = re.compile(r"\w{1,}")
		NUMCORREC_RE = re.compile(r"1|2|3")
		user_enunciado = self.request.get('enunciado')
		user_resp1 = self.request.get('resp1')
		user_resp2 = self.request.get('resp2')
		user_resp3 = self.request.get('resp3')
		user_numcorrec = self.request.get('numcorrec')
		user_tema = self.request.get('tema')
		sani_enunciado = escape_html(user_enunciado)
		sani_resp1 = escape_html(user_resp1)
		sani_resp2 = escape_html(user_resp2)
		sani_resp3 = escape_html(user_resp3)
		sani_numcorrec = escape_html(user_numcorrec)
		sani_tema = escape_html(user_tema)
		enunciado_error = ""
		resp1_error = ""
		resp2_error = ""
		resp3_error = ""
		numcorrec_error = ""
		tema_error = ""
		error = False
		if not valid_enunciado(user_enunciado):
			enunciado_error = "Anade una pregunta"
			error = True
		if not valid_resp1(user_resp1):
			resp1_error = "Anade una respuesta"
			error = True
		if not valid_resp2(user_resp2):
			resp2_error = "Anade una respuesta"
			error = True
		if not valid_resp3(user_resp3):
			resp3_error = "Anade una respuesta"
			error = True
		if not valid_numcorrec(user_numcorrec):
			numcorrec_error = "Anade el numero de la respuesta correcta"
			error = True
		if not valid_tema(user_tema):
			tema_error = "Anade un tema"
			error = True
		if error:
			self.write_form(sani_enunciado, enunciado_error, sani_resp1, resp1_error, 
			sani_resp2, resp2_error, sani_resp3, resp3_error, sani_numcorrec, numcorrec_error, sani_tema, tema_error)
		else:
			p=Pregunta()
			p.enunciado=user_enunciado
			p.resp1=user_resp1
			p.resp2=user_resp2
			p.resp3=user_resp3
			p.numcorrec=user_numcorrec
			p.tema=user_tema
			p.put()
			self.write_form()
			self.response.out.write("<p>Pregunta anadida correctamente</p>")

class Ver(session_module.BaseSessionHandler):
	def get(self):
		if self.session.get('usuario'):
			self.response.write(VER_HTML)
			p= Pregunta.query().count()
			if p==0:
				self.response.out.write("<p>No hay preguntas</p>")
			else:
				preguntas = ndb.gql("SELECT * FROM Pregunta")
				
				i=1
				for pregunta in preguntas:
					self.response.out.write('<table>')
					self.response.out.write('<tr><td style="color:#000000">Pregunta '+str(i)+'</td></tr>')
					self.response.out.write('<tr><td>'+pregunta.enunciado+'</td></tr>')
					self.response.out.write('<tr><td>1. '+pregunta.resp1+'</td></tr>')
					self.response.out.write('<tr><td>2. '+pregunta.resp2+'</td></tr>')
					self.response.out.write('<tr><td>3. '+pregunta.resp3+'</td></tr>')
					self.response.out.write('<tr>')
					self.response.out.write('<td>Numero de respuesta correcta:</td>')
					self.response.out.write('<td>'+pregunta.numcorrec+'</td>')
					self.response.out.write('</tr>')
					self.response.out.write('<tr>')
					self.response.out.write('<td>Tema: '+pregunta.tema+'</td>')
					self.response.out.write('</tr>')
					self.response.out.write('</table>')	
					self.response.out.write('</br>')
					i=i+1
							
		else:
			self.redirect('/')
		
class Logout(session_module.BaseSessionHandler):
    def get(self):
        if self.session.get("usuario"):
			self.session.pop('usuario')
			self.redirect('/')
		
app = webapp2.WSGIApplication([
	('/', Inicio),
    ('/registro', Registro),
	('/welcome', Welcome),
	('/anadir', Anadir),
	('/ver', Ver),
	('/logout', Logout)
],config=session_module.myconfig_dict, debug=True)
