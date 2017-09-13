import requests, csv
from bs4 import BeautifulSoup
from collections import defaultdict

class CVEDetailsSearch:

	def __init__(self):
		return None

	def main(self):
		cve_url = input('Paste the link from CVEDetails you want to copy here: ')
		search_string = input('Insert the value we\'re looking for. Simply enter if we don\'t want to search for anything: ')
		filename = input('Insert filename for the CSV we\'ll create. If none is entered we\'ll use temp_cve: ')

		r = requests.get(cve_url)

		if(r.status_code == 200):
			req_text = r.text
			vuln_list = self.get_vuln_list(req_text)
			link_list = self.get_paging_list(req_text)

			for link in link_list:
				link_text = self.get_link_text(link)
				new_vuln_list = self.get_vuln_list(link_text)
				# We extend the current list with the list we get
				vuln_list = {**vuln_list, **new_vuln_list}

			v_list = self.filter_list(vuln_list, search_string)

			if filename:
				self.write_to_csv(v_list,filename)
			else:
				self.write_to_csv(v_list)

		else:
			print('Problem with the URL')
			return None

	def filter_list(self, vuln_list, search_string):
		# If there is no search term we skip the search.
		if not search_string:
			return vuln_list

		# Look for the item in the description, if it exists we do nothing, otherwise we delete the csv.
		keys_to_drop = []
		for key, vals in vuln_list.items():
			if not search_string in vals[8]:
				keys_to_drop.append(key)

		for key in keys_to_drop:
			del vuln_list[key]

		return vuln_list

	def write_to_csv(self,values, filename = 'temp_cve'):
		filename = filename + '.csv'
		cve_list = []
		for key, vals in values.items():
			x = [key]
			x.extend(vals)
			cve_list.append(x)

		cve_list = sorted(cve_list, key=lambda cve_list:float(cve_list[2]), reverse=True)
		cve_list_titles = [['CVE', 'Resumen', 'Severidad', 'Acceso', 'Complejidad', 'Autenticación', 'Confidencialidad', 'Integridad', 'Disponibilidad', 'Descripción']]
		cve_list = cve_list_titles + cve_list

		with open(filename, 'w', newline='') as f:
			writer = csv.writer(f, dialect='excel')
			writer.writerows(cve_list)
			print('Se creo el archivo "'+filename+'" con éxito')

	def get_link_text(self,link):
		link = 'https://www.cvedetails.com'+ link
		r = requests.get(link)
		if(r.status_code == 200):
			return r.text
		else:
			raise Exception('The link did\'t work! This is the link that malfunctioned: \n'+link)

	def get_paging_list(self, page):
		bs = BeautifulSoup(page, 'html.parser')
		link_list = []
		# Find the relevant paging div
		paging = bs.find_all(id='pagingb')
		paging = paging[0].find_all('a')
		# Go through the links
		for l in paging:
			link = l['href']
			link_list.append(link)
		return link_list

	def get_vuln_list(self, get_text):
		bs = BeautifulSoup(get_text, 'html.parser')
		cve_table = bs.find_all(id='vulnslisttable')[0]
		# Removes the label row
		cve_table = cve_table.find_all('tr')[1:]
		# shows every second item and every second item after the first respectively
		cve_rows = cve_table[::2]
		cve_deets = cve_table[1::2]

		cve_dict = defaultdict(list)

		for cve, cve_details in zip(cve_rows,cve_deets):
			x = cve.find_all('td')
			# Dict index
			cve_number = x[1].a.text
			# 0
			cve_resumed = x[4].text.strip()
			# 1
			cve_severity = x[7].div.text
			# 2
			cve_access = x[9].text
			# 3
			cve_complexity = x[10].text
			# 4
			cve_authentication = x[11].text
			# 5
			cve_conf = x[12].text
			# 6
			cve_integ = x[13].text
			# 7
			cve_avail =  x[14].text
			# If string for resumed vul is empty we state the resumed version is not available.
			if not cve_resumed:
				cve_resumed = 'N/A'
			# 8
			cve_description = cve_details.td.text.strip()
			# Append values to CVE dictionary
			cve_dict[cve_number].extend([cve_resumed,cve_severity,cve_access, cve_complexity, cve_authentication, cve_conf, cve_integ,cve_avail,cve_description])
		
		return cve_dict

if __name__ == '__main__':
	cve_search = CVEDetailsSearch()
	cve_search.main()