"""
This object is a collection of different method to train a classifier to
detect steg content from benign http

AUTHORS:

 - Vmon (vmon@riseup.net) 2012: Initial version. fail2ban_regex method
 - Vmon Feb 2013: Unfriending TrainingSet and Train2Ban in order to
                  Regulate use of training subsets
 - Vmon July 2013: Adding the ability to associate bad regexs to each log
                   Separately
 - Vmon August 2013 Adapted to Demystegofier 

"""
#importing filter from fail2ban
#TODO:: We need to find it or include fail2ban source in ours
from os.path import dirname, abspath
from os import getcwd, chdir
import sys
#sys.path.append('/Users/bernard/NotSynced/Github/fail2ban/server')
import pickle
import base64
import math

try:
    src_dir  = dirname(dirname(abspath(__file__)))
except NameError:
    #the best we can do to hope that we are in the test dir
    src_dir = dirname(getcwd())

sys.path.append(src_dir)

class DemystegofierTrainer:
    """
    The class receives a classifier, the user then can add feature dics while 
    indicating if it is bengin or stegonized, the FEATURE_index 0 indicating 
    the class of the packet

    The steg packet will be flagged 1 and the good one by 0

    Finally when the user is satisfied with the training data they can call
    train to train the classifier.

    """
    TARGET_KEY = 0
    TARGET_BENIGN_PACKET = 0
    TARGET_STEG_PACKET = 1
    def __init__(self, demystegoclassifier):
        """
        Sets the classifier, initiate other objects.

        Because ban_classifer is an object, self gets a reference to it and
        after training it is ready to use.

        INPUT:
           demystegoclassifier: an svm object to be trained.

        """
        self._demystegoclassifier = demystegoclassifier

    def set_training_sample(self, feature_db):
        """
        Gets a dictionary cooked up by feature gathering classes
        and put them in the format of TrainigSet

        INPUT:
            feature_db: A list of dictionaries, each entry's index [0] indicates
                        the class, after that each item is feature for training

        """
        self._training_set = []
        self._key_to_index = {}
        self._target = []

        import pdb
        #using the first entry we make up the key_to_index 
        i = 0
        for cur_key in feature_db[0]:
            #ignore the target column
            if (cur_key != self.TARGET_KEY):
                self._key_to_index[cur_key] = i
                i+=1

        for cur_packet_stat in feature_db:
            self._target.append(cur_packet_stat[self.TARGET_KEY])
            cur_training_row = [0]* len(self._key_to_index)
            for cur_key in cur_packet_stat:
                if (cur_key != self.TARGET_KEY):
                    cur_training_row[self._key_to_index[cur_key]] = cur_packet_stat[cur_key]
            self._training_set.append(cur_training_row)


    def get_training_set(self):
        """
        Access function for the training set
        """
        return self._training_set

    def set_training_set(self, prepared_training_set):
        """
        As it desirable to re-use some of the information in the training set
        one can retrieve a subset of a training set and re-set it again.
        However, this function should be used caustiously as the trainer
        accept the set without checking it (at least at the momemnt hence
        TODO!)
        """
        self._training_set = prepared_training_set

    def predict(self, feature_db):
        """
        For a given data set use the currently constructed model
        to predict class labels for the entities
        """
        if (not self._key_to_index):
            raise ValueError, "key to index dict is not initialized, did you forget training the classifier?"

        for cur_packet_stat in feature_db:
            cur_training_row = [0]* len(self._key_to_index)
            for cur_key in cur_packet_stat:
                if (cur_key[0] != self.TARGET_KEY):
                    cur_training_row[self._key_to_index[cur_key]] = cur_packet_stat[cur_key]
            self._training_set.append(cur_training_row)

        self.bad_ip_prediction = self._ban_classifier.predict(ip_set._ip_feature_array)

        failList.extend([ip_set._ip_index[i] for i in range(0, len(self.bad_ip_prediction)) if self.bad_ip_prediction[i] == ip_set.BAD_TARGET])

        return failList

    def train(self):
        """
        simply run the train procedure of the classifier

        If all ips are good no actual training will happen
        """
        #first user should mark bad ips

        #If all ips ar good there's nothing to train
        if sum(self._target):
            self._demystegoclassifier.fit(self._training_set, self._target)

    def score(self):
        """
        use the sklearn score function to assess the qulitiy of the prediction
        of the classifier
        """
        if (not self._key_to_index):
            raise ValueError, "key to index dict is not initialized, did you forget training the classifier?"

        return self._demystegoclassifier.score(self._training_set, self._target)
        
