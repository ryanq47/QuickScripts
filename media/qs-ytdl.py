#!/usr/bin/python3
import argparse
import time

error_block = "[!]" # presents option to contiue
operation_block = "[*]" # standard operation
unrecov_error_block = "[X]" # unrecoverable, no option to continue
input_block = "[>]" # for getting  user input

'''
Little decorator note (still a newer concept to me), instead of running the function that the @ is above, it 
tells python to run the @function instead, and calls the function under the decorator in the process

'''
def execution_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Execution time: {execution_time:.4f} seconds")
        return result
    return wrapper

class YTDL:
    def __init__(self, url, savelocation, method):
        if not self._valuecheck(url, savelocation, method):
            exit()
        
        self.url = url
        self.savelocation = savelocation
        self.method = method

    def __str__(self):
        return "=== Details URL: {} SaveLocation: {} Method: {}===".format(self.url, self.savelocation, self.method)


    def _valuecheck(self, url, savelocation, method):
        '''
        This method is a double check that items are the right types/values. if running as a one off, argparse checks as well.
        This is mainly for bulletproofing/making it apparent where you screwed up.
        '''
        if not isinstance(url, str):
            print("{} url parameter is the incorrect type: {}, {}. Expected a string.".format(error_block, url, type(url)))
            if not QsUtils.continue_anyways():
                return False
            
        if not isinstance(savelocation, str):
            print("{} savelocation parameter is the incorrect type: {}, {}. Expected a string.".format(error_block, savelocation, type(savelocation)))
            if not QsUtils.continue_anyways():
                return False    
            
        if not isinstance(method, str) or method not in ["advanced", "simple"]:
            print("{} method parameter is the incorrect type or value: {}, {}. Expected a string, with a value of 'advanced', or 'simple'.".format(error_block, method, type(method)))
            if not QsUtils.continue_anyways():
                return False    
                
        return True
    
    @execution_time
    def main(self):
        print("{} Starting qs-ytdl".format(operation_block))
        ## add error check in _valuecheck with these 2 values
        if self.method == "simple":
            self.simple_download()
        elif self.method == "advanced":
            self.advanced_download()

    def simple_download(self):
        try:

            video_url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

            # Create a YouTube object
            yt = YouTube(video_url)

            # Get the highest resolution video stream
            video_stream = yt.streams.get_highest_resolution()

            video_stream.download()

        except Exception as e:
            print("{} Error occured while downloading video: {}".format(unrecov_error_block, e))
            exit()

        print("{} Video downloaded successfully to: {}".format(operation_block, self.savelocation))

    def advanced_download(self):
        try:
            print("{} Please select the stream you would like to download (may take a second to load...)".format(operation_block))

            yt = YouTube(self.url)
            streams = yt.streams.filter(file_extension='mp4')
            for stream in streams:
                print(stream)            
                
            itag = str(input("{} Enter itag #: ".format(input_block)))
            print("{} Downloading...".format(operation_block))
            stream = yt.streams.get_by_itag(itag)
            stream.download(timeout=None)
        
        except Exception as e:
            print("{} Error occured while downloading video: {}".format(unrecov_error_block, e))
            exit()

        print("{} Video downloaded successfully to: {}".format(operation_block, self.savelocation))



class QsUtils:
    '''
    A static class used for tools accross the QS scripts
    '''

    @staticmethod
    def send_to(dest):
        '''
        Send data to a server/other PC. Handy for getting data out
        '''
        try:
            ip, port = dest.split(':')
        
        except Exception as e:
            print("{} Error occured when getting IP & Port for sending data: {}".format(error_block, e))

        # the algorithms send func

    @staticmethod
    def continue_anyways():
        '''
        A little function that propmts the user to continue anyway. Returns true/false. 
        '''
        if input("Enter 'y' to continue execution (high chance of failure), or any other key to exit: ") == "y":
            return True
        else:
            return False

if __name__ == "__main__":
    '''Parser is down here for one-off runs, as this script can be imported & used in other pyprojects'''
    parser = argparse.ArgumentParser(
                        prog='qs-ytdl',
                        description='''The QuickScripts Youtube Downloader. Only one non-standard library is required: pytube. 
                        Note: Currently not working, as youtube changed something & broke links.
                        Current fix:

                        git clone https://github.com/oncename/pytube.git;
                        cd pytube;
                        pip install .

                        ''',
                        epilog='-- Designed by ryanq.47 --')

    parser.add_argument('-u', '--url', help="The URL of the video you want to download. Example: 'qs-ytdl -u \"https://www.youtube.com/watch?v=123\" WARNING! You must put the URL in double quotes if there is an '&', otherwise it backgrounds the task'", 
                        required=True, type=str) 
    parser.add_argument('-s', '--savelocation', help="The location you want to save the video in. Default is current dir'", type=str, default="./") 
    parser.add_argument('-m', '--method', help="'advanced' or 'simple' download. Advanced lets you choose specifics. Default is simple", default="simple") 

    parser.add_argument('-d', '--debug', help="Print debug information", action="store_true") 

    args = parser.parse_args()

    # display -h/help if no flags are supplied
    if not any(vars(args).values()):
        parser.print_help()
        # the exit makes sure the class instances don't get created/cause any errors with no values
        exit()


    try:
        from pytube import YouTube
    except ImportError as ie:
        print("{} Import Error: {}".format(error_block, ie))
        if not QsUtils.continue_anyways:
            exit()

    ytdl = YTDL(
        url = args.url,
        savelocation = args.savelocation,
        method = args.method
    )

    # Logic tree
    if args.debug:
        print(ytdl)

    # run class instance

    ytdl.main()
