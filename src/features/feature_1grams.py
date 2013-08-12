"""
For each packet, compute all 1grams of 256 characters and return it
as 256 element dict

AUTHORS::
    
    - Vmon (vmon@equalit.ie) 
      -2012 Initial version
      -2013 adopted for demystegofier

"""
from demystegofier_feature import DemystegofierFeature

class FeatureAverage1Grams(DemystegofierFeature):
    def __init__(self):
        """
        Simply calls the parent constructor
        """
        DemystegofierFeature.__init__(self)
        
        #Each feature need to have unique index as the field number
        #in ip_feature_db
        self._FEATURE_INDEX = 1


    def compute(self, pcap_packet_buf):
        """
        compute the average 1gram statistics (that is the relative quantity 
        occurance of each character) and return it in form of a dict consisting of
        256 {(1, char_no), average)} items
        """
        if (not len(pcap_packet_buf)):
            raise ValueError, "Can not compute the 1-garms stat of an empty packet"

        #init the dict to zero for each character
        stat_result_dict = {(self._FEATURE_INDEX, k): 0 for k in range(0,256)}
        for i in pcap_packet_buf:
            stat_result_dict[(self._FEATURE_INDEX, ord(i))] += 1

        for i in range(0,256):
            stat_result_dict[(self._FEATURE_INDEX, i)] /= float(len(pcap_packet_buf))

        return stat_result_dict
