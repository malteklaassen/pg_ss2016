from pyvirtualdisplay import Display
from selenium import webdriver
from time import sleep

url = 'http://localhost:8080'

display = Display(visible=0, size=(800, 600))
display.start()
driver = webdriver.Chrome()
print "Fetching /"
driver.get(url + '/')
sleep(2)
print "Fetching /ssl.html"
driver.get(url + '/ssl.html')
sleep(2)
print "Fetching /malte/gm.html"
driver.get(url + '/malte/gm.html')
sleep(2)
print "Done"

