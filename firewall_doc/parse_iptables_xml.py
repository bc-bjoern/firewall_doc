#!/usr/bin/env python2

"""
parse the output of iptables_xml command
and return a html table
"""

import re
import bs4 as bs


class ParseIptables():
    """
    Class to parse server XML Files
    """
    def __init__(self, xml_file):
        """
        load xml_file
        """
        input_file = open(xml_file)
        page = input_file.read()

        self.soup = bs.BeautifulSoup(page, "lxml")

    def parse_file(self):
        """
        make a html table
        """
        complete = ''
        html_table = ''
        for xml_table in self.soup.find_all("table"):
            table_attr = dict(xml_table.attrs)
            table_name = table_attr['name']

            table = ''
            table_headline = '\n\n<h2>' + table_name + '</h2>'
            table_prefix = ''
            table_suffix = '\n\t</tbody>\n\t</table>'

            for chain in xml_table.find_all("chain"):
                chain_attr = dict(chain.attrs)
                chain_name = chain_attr['name']
                table_data = ''

                if chain_name not in ('DOCKER-USER', 'DOCKER', 'DOCKER-ISOLATION-STAGE-2', 'DOCKER-ISOLATION-STAGE-1', 'PREROUTING', 'POSTROUTING'):
                    table_prefix = ''
                    table_prefix += '\n\n\t<h3>' + chain_name + '</h3>'
                    table_prefix += '\n\n\t<table class=\"wrapped\"><colgroup><col /><col /><col /><col /></colgroup><tbody><tr><th>Source</th><th>Target</th><th>Protocol</th><th>Condition</th><th colspan=\"1\">Dest-Port</th><th>Action</th><th>Comment</th></tr>\n'

                    for i in chain.find_all("rule"):
                        table_data += '<tr>'
                        for condition in i.find_all('conditions'):
                            if condition.find_all('match'):
                                for match in condition.find_all('match'):
                                    if match.find('s'):
                                        source = match.s.string
                                        table_data += '<td>' + source + '</td>'
                                    else:
                                        table_data += '<td>ALL</td>'

                                    if match.find('d'):
                                        dest = match.d.string
                                        table_data += '<td>' + dest + '</td>'
                                    else:
                                        table_data += '<td>ALL</td>'

                                    if match.find('p'):
                                        protocol = match.p.string
                                        table_data += '<td>' + protocol + '</td>'
                                    else:
                                        table_data += '<td></td>'
                            else:
                                table_data += '<td>ALL</td><td>ALL</td><td>ALL</td>'

                            if condition.find_all('state'):
                                if condition.state.state.string is not None:
                                    state = condition.state.state.string
                                    table_data += '<td>' + state + '</td>'
                                else:
                                    table_data += '<td></td>'
                            else:
                                table_data += '<td></td>'

                            if condition.find_all('multiport'):
                                if condition.find('multiport'):
                                    if condition.multiport.find('dports'):
                                        dports = condition.multiport.dports.string
                                        table_data += '<td>' + dports + '</td>'

                            if condition.find_all('tcp'):
                                if condition.find('tcp'):
                                    if condition.tcp.find('dport'):
                                        dport = condition.tcp.dport.string
                                        table_data += '<td>' + dport + '</td>'

                            if not condition.find_all('multiport') and not condition.find_all('tcp'):
                                table_data += '<td></td>'

                        if i.find('actions'):
                            for action in i.find_all('actions'):
                                actions = action.contents

                                if len(actions) > 2:
                                  del actions[0]
                                  del actions[1]

                                actions = str(actions)
                                matchobj = re.match(r'\[<(.*)>(.*)</(.*)>\]', actions, re.M|re.I)
                                if matchobj:
                                    if '>' in matchobj.group(1):
                                        splitstr = matchobj.group(1).split('>')
                                        table_data += '<td>' + splitstr[0] + '</td>'
                                    else:
                                        table_data += '<td>' + matchobj.group(1) + '</td>'
                        else:
                            table_data += '<td></td>'

                        if i.find('comment'):
                            comment = i.comment.comment.string.replace('"', '')
                            table_data += '<td>' + comment + '</td>'
                        else:
                            table_data += '<td></td>'

                        table_data += '</tr>\n'

                    table += table_prefix + table_data + table_suffix
            complete += table_headline + table
            html_table = complete
        return html_table


if __name__ == "__main__":
    XML_TABLE = ParseIptables('./input/iptables-xml_output.xml')
    TABLE = XML_TABLE.parse_file()
    print TABLE
