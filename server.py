import web, json
from web import form
import re, os, subprocess
import base64

render = web.template.render('templates/')

urls = (
    '/','Index',
    '/login','Login',
	'/getOUs', 'getOUs',
	'/getNames', 'getNames',
	'/setPass', 'setPass'
)

app = web.application(urls,globals())

allowed = []
c = open("config.dat", 'r')
config = json.load(c)
c.close()
users = config["Users"]
for user in users:
    userObj = (user[0].encode("ascii"), user[1].encode("ascii"))
    allowed.append(userObj)

class Index:
    def GET(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            return render.base()
        else:
            raise web.seeother('/login')

class Login:
    def GET(self):
        auth = web.ctx.env.get('HTTP_AUTHORIZATION')
        authreq = False
        if auth is None:
            authreq = True
        else:
            auth = re.sub('^Basic ','',auth)
            username,password = base64.decodestring(auth).split(':')
            if (username,password) in allowed:
                raise web.seeother('/')
            else:
                authreq = True
        if authreq:
            web.header('WWW-Authenticate','Basic realm="Auth example"')
            web.ctx.status = '401 Unauthorized'
            return

class getOUs:
	def POST(self):
		w = open("getOUs.ps1", 'w')
		w.write("import-module ActiveDirectory -Force\n")
		#w.write("#requires -Modules ActiveDirectory")
		w.write("Get-ADOrganizationalUnit -LDAPFilter '(name=*)' -SearchBase 'OU=Students,DC=School,DC=edu' -SearchScope OneLevel | ft Name | Out-File C:\folder\YOGs.txt\n")
		w.close()
		cmd = subprocess.Popen(["C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe", "-ExecutionPolicy", "Unrestricted", ".\"./getOUs.ps1\";"])
		OUs = open("YOGs.txt", 'r')
		OUs.readline()
		OUs.readline()
		OUs.readline()
		ouArray = []
		for each in range(0, 13):
			line = OUs.readline()
			line = re.sub(r'\W+', '', line)
			ouArray.append(line)
		web.header('Content-Type', 'application/json')
		return json.dumps({'ouArray': ouArray})
		
class getNames:
	def POST(self):
		YOG = web.input().Year
		fileName = YOG+"names.txt"
		filePath = os.path.normpath("C:\\folder\\"+fileName)
		w = open("get"+YOG+"Names.ps1", 'w')
		w.write("import-module activedirectory -Force\n")
		w.write("Get-ADUser -LDAPFilter '(name=*)' -SearchBase 'OU="+YOG+",OU=Students,DC=School,DC=edu' -SearchScope OneLevel | ft SamAccountName | Out-File "+filePath+"\n")
		w.close()
		cmd = subprocess.Popen(["C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe", "-ExecutionPolicy", "Unrestricted", ".\"./get"+YOG+"names.ps1\";"])
		names = open(fileName, 'r')
		names.readline()
		names.readline()
		names.readline()
		nameArray = []
		for each in names:
			each = re.sub(r'\W+', '', each)
			count = 0
			index = 0
			for char in each:
				if char.isupper() == 1:
					count += 1
					if count == 2:
						accountName = each[:index]+'.'+each[index:]
				index += 1
			if count < 2:
				continue
			nameArray.append(accountName)
		web.header('Content-Type', 'application/json')
		return json.dumps({'nameArray': nameArray})
		
class setPass:
	def POST(self):
		global status
		userName = web.input().userName
		value = web.input().password
		w = open("changePassword.ps1", 'w')
		w.write("import-module activedirectory -Force\n")
		w.write("$userpwd = ConvertTo-SecureString "+value+" -AsPlainText -Force\n")
		w.write("Set-ADAccountPassword "+userName+" -NewPassword $userpwd\n")
		w.close()
		cmd = subprocess.Popen(["C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe", "-ExecutionPolicy", "Unrestricted", ".\"./changePassword.ps1\";"])
		print "Password for "+userName+" set to: "+value
		return

			
if __name__=='__main__':
	web.internalerror = web.debugerror
	app.run()