#!/usr/bin/env python
"""
Unit tests for Train2Ban

AUTHORS:

- Vmon (vmon@equalit.ie) 2012: initial version
"""

from os.path import dirname, abspath,  isfile
from os import getcwd, chdir, listdir, path
import sys

try:
    src_dir  = dirname(abspath(__file__))
except NameError:
    #the best we can do to hope that we are in the test dir
    src_dir = dirname(getcwd())

sys.path.append(src_dir)

import dpkt

#features
from features.demystegofier_feature import DemystegofierFeature
from features.feature_1grams import FeatureAverage1Grams

#training tools
from sklearn import svm
from trainer import DemystegofierTrainer

class Demystegofier:
    def __init__(self):
        """Call before every test case."""

        #we are testing trainin
        self.trainer = DemystegofierTrainer( svm.SVC(kernel='linear'))
        self.feature_db = []

    def add_packet_path(self, packet_path, target_mark):
        """
        read all files in steg_packet_path and compute all features against
        the packet inside them. Then mark them as the target and add them
        to the feature_db

        INPUT::
            steg_packet_path: the directory that contain the pcap files containing
                              packets
            target_mark:  indicates if the path contains steg packet
                          (TARGET_STEG_PACKET) or bengin http (TARGET_BENIGN_PACKET)
        """
        for cur_payload_filename in listdir(packet_path):
            cur_payload_filename = path.join(packet_path, cur_payload_filename)
            if isfile(cur_payload_filename):
                cur_payload_file = open(cur_payload_filename)
                cur_pcap = dpkt.pcap.Reader(cur_payload_file)

                for ts, buf in cur_pcap:
                    cur_pcap_stat_dic = {}
                    for CurrentFeatureType in DemystegofierFeature.__subclasses__():
                        cur_feature_tester = CurrentFeatureType()
                        cur_pcap_stat_dic.update(cur_feature_tester.compute(buf))

                        cur_pcap_stat_dic[DemystegofierTrainer.TARGET_KEY] = target_mark
                        self.feature_db.append(cur_pcap_stat_dic)

    def train_trainer(self):
        """
        simply calls the train function of the trainer. This basically marks
        the end of adding training data
        """
        self.trainer.set_training_sample(self.feature_db)
        self.trainer.train()

    def score(self):
        return self.trainer.score()

    def dispUsage(self):
        """
        prints demystegofier usage
        """
        print "Usage: "+self.__argv[0]+" bengin_packet_dir steg_packet_dir"

if __name__ == "__main__":
    import pdb
    demystegofier = Demystegofier()

    if (len(sys.argv) < 3):
        demystegfier.dispUsage()
        sys.exit(-1)

    demystegofier.add_packet_path(sys.argv[1], DemystegofierTrainer.TARGET_BENIGN_PACKET)
    demystegofier.add_packet_path(sys.argv[2], DemystegofierTrainer.TARGET_STEG_PACKET)
    demystegofier.train_trainer()
    print "Demystegofier can detect steg packets from benign packets with accuracy:", demystegofier.score()
