"""
The parent class for all features used to distinguished benign HTML from one that carries steg data

AUTHORS ::
    
    - Vmon (vmon@riseup.net) 2012: Initial version, 
           - Adopted for features of demystegfier (August 2013).

"""
class DemystegofierFeature(object):
    """
    We need to get packet and analyze it and compute the corresponding feature 
    and it to the db

    (This is new-style particularly to loop through its children using 
    __subclass__)
    """
    def __init__(self):
        """
        Set the feature universal index
        
        INPUT::
        """
        self._FEATURE_INDEX = -1 #This is an abstract class so no real feature

    def compute(self, pcap_packet_buf):
        """
        The feature should overload this function to implement the feautere 
        computation. At the end the results should be returned in form of a
        dictionary of ((FEATURE_INDEX, subindex), value)
        """
        pass

