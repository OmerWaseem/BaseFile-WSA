import os
import argparse 
from bs4 import BeautifulSoup
from bs4 import Comment
from urllib.parse import urlparse
import requests
import validators
import yaml

parser = argparse.ArgumentParser(description='The Achilles HTML Vulnerability Analyzer Version 1.0')

parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0 ')
parser.add_argument('url', type=str, help='The URL of the HTML to analyze')
parser.add_argument('--config', help='Path to configuration file')
parser.add_argument('-o', '--output', help='Report file output path')

args = parser.parse_args() #checks the type of argument(input) and categorises it in the correct argument type.
link = args.url 

default_config = {'forms': True, 'comments': True,'passwords': True}

header = "Web Security Analyzer V 1.0 \n"
header += "====================================================\n\n"

if(args.config):
    
    config_file = open(args.config, 'r')
    config_from_user = yaml.load(config_file, Loader=yaml.FullLoader)
    
    if(config_from_user):
        print('Using config file: ' + args.config + '\n')
        #default_config = config_from_user #remove this line if you want to make use of merged dictionaries. if a key is missing in config_from_user then it will merge with default config. So remove this line if you want to make use of merged
        default_config = {**default_config, **config_from_user}
        
    else:
        print('Using default config file \n')


#extract host name 
def extract_hostname(link):
    hostname = os.path.dirname(link)
    return hostname

if (validators.url(link)):
    result_html = requests.get(link).text
    parsed_html = BeautifulSoup(result_html,'html.parser')

    forms           = parsed_html.find_all('form') #prints out any form that is found. The same can be done for anchors, headings, etc.
    comments        = parsed_html.find_all(string=lambda text:isinstance(text,Comment))
    password_inputs = parsed_html.find_all('input', {'username' : 'password'}) # dictionary used here as an extra filter where it matches and filters only those name with passwords   

    hostname = extract_hostname(link) 
    report = ''
    link_scheme = urlparse(link).scheme

    if(link_scheme =='https'):
        report+= 'SSL Secure (Includes HTTPS). \n'
    else:
        report+= 'Insecure SSL. Provided Link doesn\'t include HTTPS. \n'


    if(default_config['forms']):
        for form in forms:
            if((form.get('action').find('https') < 0 )): # < 0 because the return for first condition is -1 is false
                new_url = hostname + '/' + form.get('action')
                response = str(requests.get(new_url).status_code) 
                
                if(response == '200'):
                    
                    report += form.get('action') + "'s status code is " + response + '\n'
                    if (urlparse(new_url).scheme != 'https'): 
                        form_secure = False
                        
                        report += 'Insecure Form action! ' + form.get('action') + ' is not secure. \n'
                    else:
                        report += form.get('action') + ' is secure with https. \n'             
                else:
                    report += new_url + ' is not working.' + 'Error Code: ' + response                                
            else:
                report += form.get('action') + ' includes https so form is secure. \n'            
                
                    
    if(default_config['comments']):
        if len(comments) == 0:
            report += 'No keys found in the comment. \n'
        else:
            for comment in comments:
                if(comment.find('key: ') > -1):
                    report += 'Comment Issue! A Key is found in the HTML code in comments. Please remove the key. \n'
                           
    if(default_config['passwords']):
        if len(password_inputs) == 0:
            report += 'No password fields found! \n'
        else:    
            for password_input in password_inputs:
                if(password_input.get('type') !='password' ):
                    report += 'Password Input Issue! Plaintext password input was found. Please change to password type. \n'         
                else:
                    report += 'Password type used for password field. No password input issue. \n'            
    if(args.output):
        f = open(args.output,'w')
        f.write(header)
        f.write(report)
        f.close()
        print('Report saved to: ' + args.output)
    print(report)        

else:
    print('Link is not valid. Please input valid link')

