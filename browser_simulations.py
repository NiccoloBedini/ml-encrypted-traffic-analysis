import os
import time
import shutil
import logging
import subprocess
import pandas as pd
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


logging.basicConfig(filename='log_file.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s')


def firefoxSimulation(function, number_iterations, website, key, csv_path, tstat_path):
  """Simulates the firefox browser and creates the tstat files related to the packets captured during the simulations

    
    function: the function that represents the behaviour of a website(ex. googleSearch) 
    number_iterations: represents the number of iterations of the choosen function
    website: string that represents the website name associated to the function
    key: string that represents the key used inside the function
    csv_path: string that represents the path to the csv file which contains the metadata about the simulations
    tstat_path: string that represents the path to the folder which will contain all the tstat files after the simulation"""
  
  if not os.path.exists(tstat_path) and not os.path.isdir(tstat_path):
    os.mkdir(tstat_path)
  try:
    tstat_directory_path = os.path.join(os.path.abspath(tstat_path), "firefox_" + website + "_" + key)
    os.mkdir(tstat_directory_path)
    current_directory = os.path.abspath("./")
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    i = 0
    while i < number_iterations:
      driver = webdriver.Firefox(options = options)
      filename = "firefox_" + website + "_" + key + str(i) + ".pcap"
      full_path = os.path.join(tstat_directory_path, filename)
      try:
        packetCapture(function, driver, key, full_path)
      except:
        driver.quit()
        continue
      update_csv_file(csv_path, "firefox", website, key, full_path)
      driver.quit()
      i += 1
    tstatExtraction(os.path.join(current_directory, "labels.csv"), tstat_directory_path, number_iterations)
  except Exception as e:
    logging.error(f'Firefox error: {e}', extra={'website': website, 'key': key})

    
def chromeSimulation(function, number_iterations, website, key, csv_path, tstat_path):

  """Simulates the chrome browser and creates the tstat files related to the packets captured during the simulations

    
    function: the function that represents the behaviour of a website(ex. googleSearch) 
    number_iterations: represents the number of iterations of the choosen function
    website: string that represents the website name associated to the function
    key: string that represents the key used inside the function
    csv_path: string that represents the path to the csv file which contains the metadata about the simulations
    tstat_path: string that represents the path to the folder which will contain all the tstat files after the simulation"""
  
  if not os.path.exists(tstat_path) and not os.path.isdir(tstat_path):
    os.mkdir(tstat_path)
  try:
    tstat_directory_path = os.path.join(os.path.abspath(tstat_path), "chrome_" + website + "_" + key)
    os.mkdir(tstat_directory_path)
    current_directory = os.path.abspath("./")
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    i = 0
    while i < number_iterations:
      driver = webdriver.Chrome(options = options)
      filename = "chrome_" + website + "_" + key + str(i) + ".pcap"
      full_path = os.path.join(tstat_directory_path, filename)
      try:
        packetCapture(function, driver, key, full_path)
      except:
        driver.quit()
        continue
      update_csv_file(csv_path, "chrome", website, key, full_path)
      driver.quit()
      i += 1
    tstatExtraction(os.path.join(current_directory, "labels.csv"), tstat_directory_path, number_iterations)
  except Exception as e:
    logging.error(f'Chrome error: {e}', extra={'website': website, 'key': key})

  
def edgeSimulation(function, number_iterations, website, key, csv_path, tstat_path):
  """Simulates the edge browser and creates the tstat files related to the packets captured during the simulations

    
    function: the function that represents the behaviour of a website(ex. googleSearch) 
    number_iterations: represents the number of iterations of the choosen function
    website: string that represents the website name associated to the function
    key: string that represents the key used inside the function
    csv_path: string that represents the path to the csv file which contains the metadata about the simulations
    tstat_path: string that represents the path to the folder which will contain all the tstat files after the simulation"""
  
  if not os.path.exists(tstat_path) and not os.path.isdir(tstat_path):
    os.mkdir(tstat_path)
  try:
    tstat_directory_path = os.path.join(os.path.abspath(tstat_path), "edge_" + website + "_" + key)
    os.mkdir(tstat_directory_path)
    current_directory = os.path.abspath("./")
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    i = 0
    while i < number_iterations:
      driver = webdriver.Edge(options = options)
      filename = "edge_" + website + "_" + key + str(i) + ".pcap"
      full_path = os.path.join(tstat_directory_path, filename)
      try:
        packetCapture(function, driver, key, full_path)
      except:
        driver.quit()
        continue
      update_csv_file(csv_path, "edge", website, key, full_path)
      driver.quit()
      i += 1
    tstatExtraction(os.path.join(current_directory, "labels.csv"), tstat_directory_path, number_iterations)
  except Exception as e:
    logging.error(f'Edge error: {e}', extra={'website': website, 'key': key})


def packetCapture(function, driver, key, pcap_path):
  """Initiates packet capture through tshark with a terminal command, starts the individual simulation, and saves the pcap file in the pcap_path

  function: the function that represents the behaviour of the a website (ex. googleSearch)
  driver: is the Selenium driver of the relative browser
  key: string that represents the key used in the function
  pcap_path: string that represents the path where will be saved the pcap file that contains the recorded traffic (used in the temporary csv)"""

  open(pcap_path, "w")
  tshark_command = ["tshark", "-i", "eth0", "-F", "pcap", "-w", pcap_path, "-f", "tcp port 80 or tcp port 443" ]
  process = subprocess.Popen(tshark_command)
  try:
    function(driver, key)
  except:
    process.terminate()
    os.remove(pcap_path)
    raise
  process.terminate()


def tstatExtraction(csv_path, tstat_path, number_iterations):
  """ The purpose of this function is to extract, from all the pcap files of a configuration obtained through tshark, the corresponding tstat files containing TCP information of the captured traffic.
  From these, the dataset will then be created.

  csv_path: this is the path that indicates the location of the CSV file
  tstat_path: is the path indicating where the tstat file will be saved, extracted from its corresponding pcap file. 
  number_iterations: is the count of times a configuration is executed. """

  current_directory = os.getcwd()
  df = pd.read_csv(csv_path, header=None)
  len_index = len(df.index) 
  start_index = len_index - number_iterations
  for i in range(start_index, len_index):
    try:
      tstat_command = ["tstat", df.iloc[i,-1]]
    except Exception as e:
      continue
    process = subprocess.Popen(tstat_command)
    time.sleep(0.1)
    os.remove(df.iloc[i,-1])
    time.sleep(2)
    process.terminate()
  os.chdir(tstat_path)
  list_dir = os.listdir()
  for i in range(len(list_dir)):
    os.chdir(list_dir[i])
    sub_list = os.listdir()
    os.chdir(sub_list[0])
    os.rename("./log_tcp_complete","./log_tcp_complete_" + str(i))
    shutil.move("./log_tcp_complete_" + str(i), tstat_path)
    os.chdir(tstat_path)
    shutil.rmtree(list_dir[i])
  os.chdir(current_directory)


def update_csv_file(csv_path, browser_name, website, key, pcap_path):
    """Update the csv file which contains the metadata about the simulations

    csv_path: string that represents the path to the csv file which contains the metadata about the simulations
    browser_name: string that represents the browser used for the simulation 
    website: string that represents the website used for the simulation
    key: string that represents the key used for the simulation 
    pcap_path: string that represents the path to the folder which contains the pcap file after the simulation"""

    with open(csv_path, "a") as labels_csv:
        labels_csv.write(browser_name+ "," +  website + "," + key + "," + pcap_path + "\n")
        labels_csv.flush()


def googleSearch(driver, key):
    """Searches the key in the search bar of google

    
    driver: selenium driver which is used for the simulation 
    key: string that represents the key used inside the function"""

    try:
      driver.get("https://www.google.com")
      time.sleep(1)  
      driver.find_element(By.ID, "L2AGLb").click()
      search_box = driver.find_element(By.ID, "APjFqb")
      search_box.send_keys(key)
      search_box.submit()
      time.sleep(1)
    except Exception as e:
      logging.error(f'googleSearch error: {e}', extra={ 'key': key})
      raise
    return 


def youtubeSearch(driver, key):
  """Searches the key in the search bar of youtube and watches the first video for 2 seconds

    
    driver: selenium driver which is used for the simulation 
    key: string that represents the key used inside the function"""
  
  try:
    driver.get("https://www.youtube.com")
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.XPATH, "/html/body/ytd-app/ytd-consent-bump-v2-lightbox/tp-yt-paper-dialog/div[4]/div[2]/div[6]/div[1]/ytd-button-renderer[1]/yt-button-shape/button/yt-touch-feedback-shape/div/div[2]"))).click()
    time.sleep(2)
    search_box = driver.find_element(By.XPATH, '/html/body/ytd-app/div[1]/div/ytd-masthead/div[4]/div[2]/ytd-searchbox/form/div[1]/div[1]/input')
    search_box.click()
    search_box.send_keys(key)
    search_box.submit()
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "video-title"))).click()
    time.sleep(1)
  except Exception as e:
    logging.error(f'youtubeSearch error: {e}', extra={ 'key': key})
    raise
  return


def ebaySearch(driver, key):
  """Search the key in the search bar of ebay
    
    driver: selenium driver which is used for the simulation 
    key: string that represents the key used inside the function"""
  
  try:
    driver.get("https://www.ebay.com")
    decline_button = WebDriverWait(driver, 15).until(EC.element_to_be_clickable((By.ID, "gdpr-banner-decline")))
    time.sleep(3)
    decline_button.click()
    search_box = WebDriverWait(driver,15).until(EC.element_to_be_clickable((By.XPATH, '/html/body/div[4]/div/header/table/tbody/tr/td[5]/form/table/tbody/tr/td[1]/div[1]/div/input[1]')))
    time.sleep(3)
    search_box.click()
    search_box.send_keys(key)
    search_box.submit()
    time.sleep(2)  
  except Exception as e:
    logging.error(f'ebaySearch error: {e}', extra={ 'key': key})
    raise
  return


def amazonSearch(driver, key):
    """Search the key in the search bar of amazon

    
    driver: selenium driver which is used for the simulation 
    key: string that represents the key used inside the function"""

    try:
      driver.get("https://www.amazon.it")
      decline_button = driver.find_element(By.ID, "sp-cc-rejectall-link")
      time.sleep(5)
      decline_button.click()
      search_box = driver.find_element(By.ID, "twotabsearchtextbox")
      time.sleep(5)
      search_box.click()
      search_box.send_keys(key)
      search_box.send_keys(Keys.RETURN)
      time.sleep(2)
    except Exception as e:
      logging.error(f'amazonSearch error: {e}', extra={ 'key': key})
      raise
    return


def datasetCreation(path):
  """Creates the dataset from the log_tcp_complete files taken from each simulation, each log_tcp_complete file contains more than one line so in order to
     obtain a single object, the mean of the lines inside the file is computed

    
    path: string that represents the path to the folder which contains all the directories with the log_tcp_complete files taken from each simulation"""
  
  os.chdir(path)
  list_dir = os.listdir()
  dataset = pd.DataFrame()
  for dir in list_dir:
    os.chdir(dir)
    labels = dir.split("_")
    list_files = os.listdir()
    for log_tcp_complete in list_files:
      df = pd.read_csv(log_tcp_complete, delimiter=" ")
      columns_to_drop = ['#15#c_ip:1', 's_ip:15', 'c_port:2', 's_port:16']
      df = df.drop(columns=columns_to_drop)
      to_remove = df.select_dtypes(include=object)
      df[to_remove.columns] = 0
      column_mean = df.mean()
      mean_df = pd.DataFrame(column_mean).transpose()
      mean_df = pd.concat([mean_df, pd.DataFrame({'browser': [labels[0]], 'website': [labels[1]], 'behaviour': [labels[2]]})], axis=1) 
      dataset = dataset._append(mean_df)
    os.chdir("..")
  dataset.to_csv("../dataset.csv", index = False)


if __name__ == "__main__":
  google_keys = ["ml","polito","amazon","trucebaldazzi","selenium"]
  amazon_keys = ["xbox","wii","ps5","gta6","switch"] 
  number_iterations = 100
  for key in google_keys:
    chromeSimulation(googleSearch, number_iterations, "google", key, "./labels.csv", "./tstat_files")
    edgeSimulation(googleSearch, number_iterations, "google", key, "./labels.csv", "./tstat_files")
    firefoxSimulation(googleSearch, number_iterations, "google", key, "./labels.csv", "./tstat_files")
    chromeSimulation(youtubeSearch, number_iterations, "youtube", key, "./labels.csv", "./tstat_files")
    edgeSimulation(youtubeSearch, number_iterations, "youtube", key, "./labels.csv", "./tstat_files")
    firefoxSimulation(youtubeSearch, number_iterations, "youtube", key, "./labels.csv", "./tstat_files")
  for key in amazon_keys:
    chromeSimulation(amazonSearch, number_iterations, "amazon", key, "./labels.csv", "./tstat_files")
    edgeSimulation(amazonSearch, number_iterations, "amazon", key, "./labels.csv", "./tstat_files")
    firefoxSimulation(amazonSearch, number_iterations, "amazon", key, "./labels.csv", "./tstat_files")
    chromeSimulation(ebaySearch, number_iterations, "ebay", key, "./labels.csv", "./tstat_files")
    edgeSimulation(ebaySearch, number_iterations, "ebay", key, "./labels.csv", "./tstat_files")
    firefoxSimulation(ebaySearch, number_iterations, "ebay", key, "./labels.csv", "./tstat_files")
  datasetCreation("./tstat_files")