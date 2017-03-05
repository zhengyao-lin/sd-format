import yhy523u
import pn532

def pn532cons(port = "/dev/ttyUSB0"):
	ret = pn532.PN532(port)
	
	# init pn532
	ret.begin()
	ret.SAM_configuration()
	
	return ret

intf = {
	"yhy523u": yhy523u.YHY523U,
	"pn532": pn532cons
};

def init(port, driver = "yhy523u"):
	if not driver in intf:
		raise Exception("no driver found for " + driver)

	return intf[driver](port)
