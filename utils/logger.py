class Logger(object):

    def __init__(self):
        self.G = "\033[92m"
        self.Y = "\033[93m"
        self.B = "\033[94m"
        self.R = "\033[91m"
        self.W = "\033[0m"

    def banner(self):
        print r"""%s

		    /\       | |
		   /  \   ___| |
		  / /\ \ / __| __| '__/ _` |
		 / ____ \\__ \ |_| | | (_| |
		/_/    \_\___/\__|_|  \__,_|


              %s""" % (self.G, self.W)
