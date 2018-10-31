import ConfigParser
import os


def get_allvalues(section):
    # Return all the values in dict format from config file
    Config = ConfigParser.ConfigParser()
    Config.read('utils/config.property')
    return dict(Config.items(section))


def get_value(filename, section, name):
    # Return only one value from config file
    if os.getcwd().split('/')[-1] == 'API':
        dir_name = '../utils/'
    else:
        dir_name = 'utils/'

    file_name = dir_name + filename
    Config = ConfigParser.ConfigParser()
    Config.read(file_name)
    return Config.get(section, name)


def update_value(section, name, value):
    # This function deals with updating value in config file
    config = ConfigParser.RawConfigParser()
    config.read('utils/config.property')
    config.set(section, name, value)
    with open('utils/config.property', 'wb') as configfile:
        config.write(configfile)
