import pygeoip

a = '213.55.73.204'

# target_addr = input('target IP: ')

geo = pygeoip.GeoIP('GeoLiteCity.dat')

res = geo.record_by_addr(a)


for key, val in res.items():
    print('\t%s: %s' %(key, val))
