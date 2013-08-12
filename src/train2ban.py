"""
This object is a collection of different method to train a classifier to
detect malicious activities in a log file

AUTHORS:

 - Vmon (vmon@equalit.ie) 2012: Initial version. fail2ban_regex method
 - Vmon Feb 2013: Unfriending TrainingSet and Train2Ban in order to
                  Regulate use of training subsets
 - Vmon July 2013: Adding the ability to associate bad regexs to each log
                   Separately

"""
#importing filter from fail2ban
#TODO:: We need to find it or include fail2ban source in ours
from os.path import dirname, abspath
from os import getcwd, chdir
import sys
#sys.path.append('/Users/bernard/NotSynced/Github/fail2ban/server')
sys.path.append('/usr/share/fail2ban/server')
import pickle
import base64
import math

try:
    src_dir  = dirname(dirname(abspath(__file__)))
except NameError:
    #the best we can do to hope that we are in the test dir
    src_dir = dirname(getcwd())

sys.path.append(src_dir)
sys.path.append(src_dir+'/fail2ban/server') #put a local symlink

from filter import Filter as Fail2BanFilter
from tools.training_set import TrainingSet

class ReconstructableModel:
    """
    A Class that contains the data that we need to use to run predict
    on the same model later. The data is:
    TODO::
    Move the save function to the class.
    - Learnt Model
    - Normalization data
    """
    def __init__(self, training_set = None, trained_classifier = None):
        """
        INPUT::
        - training_set: the training set that containt the normalisation data for prediction.
        - trained_classifier: the (svm) classifier that is trained and is goining to be used
          for prediction.
        """
        if training_set:
            self.normalisation_data = training_set._normalisation_data

        if trained_classifier:
            self.ban_classifier = trained_classifier

    @classmethod
    def construct_from_stored_model(cls, model_filename):
        """
        Constructs a Reconstructable model by loading the stored model in the file

        INPUT::
          - model_filename: the filename where the model is stored.

        OUTPUT::
          - The constructed model
        """
        self_inst = cls()
        self_inst.load_model(model_filename)

        return self_inst

    def save_model(self, model_filename):
        try:
            pickle_object = {}
            pickle_object['model'] = self
            pickled_model = pickle.dumps(pickle_object)
            base64_encoded_pickled_model = base64.b64encode(pickled_model)
            f = open(model_filename, 'w')
            f.write(base64_encoded_pickled_model)
            f.close()
            return base64_encoded_pickled_model
        except Exception, e:
            return str(e)

    def load_model(self, model_filename):
        """
        reset the info of the model to what is pickled in the file
        """
        try:
            f = open(model_filename, 'r')
            base64_encoded_model = f.read()
            pickled_model = base64.b64decode(base64_encoded_model)
            pickle_object = {}
            pickle_object = pickle.loads(pickled_model)
            #I might be able to brutally load in self but let be careful
            temp_constructable_model = pickle_object['model']
            self.ban_classifier = temp_constructable_model.ban_classifier
            self.normalisation_data = temp_constructable_model.normalisation_data
            f.close()
            return True
        except Exception, e:
            return str(e)

class Train2Ban:
    """
    The class receives a classifier, the user then can add ip+feature dics.
    Each ip is considered innocent unless proven otherwise. User can call
    different methods to indicate bad ips.

    It also hase the ability of using regex (through Fail2BanFilter) to mark
    bad ips

    The bad ips will be flagged 1 and the good one by 0

    Finally when the user is satisfied with the training data they can call
    train to train the classifier.

    TODO: The training set needs to know its normalisation for prediction
    """
    def __init__(self, ban_classifier):
        """
        Sets the classifier, initiate the fail2ban filter and other objects.

        Because ban_classifer is an object, self gets a reference to it and
        after training it is ready to use.

        INPUT:
           ban_classifier: an svm object to be trained.

        """
        self._ban_classifier = ban_classifier
        self._training_set = TrainingSet()
        self._log_filters = []
        self._malicious_ip_list = []
        self._log_files = []

    def add_to_sample(self, ip_feature_db):
        """
        Gets a dictionary cooked up by feature gathering classes
        and put them in the format of TrainigSet

        INPUT:
            ip_feature_db: A dictionary of lists each entry index by an ip
                           address pointing to a list of features.

        """
        for cur_ip in ip_feature_db:
            try:
                self._training_set.add_ip(cur_ip, ip_feature_db[cur_ip])
            except ValueError:
                #just ignore the second coming of the IP
                pass

    def normalise(self, method = 'individual'):
        """
        Ask the training set to normalises itself
        """
        if method == 'sparse':
            self._training_set.normalise_sparse()
        else:
            self._training_set.normalise_individual()

    def add_bad_regexes(self, log_id, bad_ip_regexes):
        """
        Submit the fail2ban regexes so when runs over the log file sieve
        out the bad ips and ip that doesn't come out of that process
        is consdier inoccent.

        If the ip doesn't already added to the training_set, the it will be
        ignored.

        INPUT:
           log_id: to which log this regex should be associated
           bad_ip_regexes: a tuple/list of fail2ban regexes to added to the
                           filter.
        """
        #first we check if we have alredy assciated any filter to this log
        cur_log_filter = [cur_filter[1] for cur_filter in self._log_filters if cur_filter[0] == log_id]
        if (len(cur_log_filter) == 0): #no filter found
            cur_log_filter = Fail2BanFilter(None)
            self._log_filters.append([log_id, cur_log_filter])
                                            #setting the jail as None because
                                            #we are only using it line by line
        else: #filter already exists
            cur_log_filter = cur_log_filter[0]

        for cur_bad_regex in bad_ip_regexes:
            cur_log_filter.addFailRegex(cur_bad_regex)

    def add_malicious_history_log_files(self, log_file_info):
        """
        Store the name of the files that fail2ban suppose to analysis to
        find out about the bad ips.

        INPUT:
              log_file_info: is an array of [log_id, log_filename]
                             where the log_id is being used to keep trak of
                             the regex associated to each log
        """
        self._log_files.extend(log_file_info)

    def add_to_malicious_ips(self, bad_ip_list):
        """
        Get a list of ips that the user knows they are malicious
        and add them to _malicious_ip_list

        INPUT:
           bad_ip_list: the ip list of strs to be indicated as 1 in training
           target
        """
        self._malicious_ip_list.extend(bad_ip_list)

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

    def predict(self, ip_feature_db):
        """
        For a given data set use the currently constructed model
        to predict class labels for the entities
        """
        failList = list()

        ip_set = self._training_set.precook_to_predict(ip_feature_db)

        self.bad_ip_prediction = self._ban_classifier.predict(ip_set._ip_feature_array)

        failList.extend([ip_set._ip_index[i] for i in range(0, len(self.bad_ip_prediction)) if self.bad_ip_prediction[i] == ip_set.BAD_TARGET])

        return failList

    def mark_bad_target(self):
        """
        Goes through all means of detecting bad ips, e.g., running fail2ban
        over log file, go through the malicious ip list and create the target
        for training. If an ip doesn't show up in any of these, it is
        considered good.

        #telling the training set that we are done with adding ips
        """
        self._training_set.initiate_target()

        #Fail2ban ip selection
        from datetime import datetime
        for (cur_log_id, cur_log_filename) in self._log_files:
            try:
                cur_log_file = open(cur_log_filename)
                cur_log_filter = [cur_filter[1] for cur_filter in self._log_filters if cur_filter[0] == cur_log_id] #there is at most one filter anyway
                if (len(cur_log_filter) > 0): #filter for this log found
                    for cur_line in cur_log_file:
                        for bad_ip in cur_log_filter[0].findFailure(str(datetime.now()), cur_line):       #TODO: this might need to be
                            #changed, for we can simply give now
                            #.strftime("%Y-%m-%d %Y %I:%M%p")
                            self._training_set.mark_as_bad(bad_ip[0])
            except IOError:
                print "Unable to read", cur_log_filename, "for marking bad ips, skipping..."

        #Manual ip selection
        for bad_ip in self._malicious_ip_list:
            self._training_set.mark_as_bad(bad_ip)

    def train(self):
        """
        simply run the train procedure of the classifier

        If all ips are good no actual training will happen
        """
        #first user should mark bad ips

        #If all ips ar good there's nothing to train
        if sum(self._training_set._target):
            self._ban_classifier.fit(self._training_set._ip_feature_array, \
                                     self._training_set._target)

    def mark_and_train(self):
        self.mark_bad_target()
        self.train()

    def save_model(self,filename):
    	"""
        Given a filename this function saves the current trainer model
        as a pickle file using the Sklearn pickle function.
        On success it returns true on failure it returns an error
        message.
        """
        model_to_save = ReconstructableModel(self._training_set, self._ban_classifier);
        model_to_save.save_model(filename)

    def load_model(self,filename):
        """
        For ao given filename this function attempts to load a pickle
        file as the current trainer model.
        On success it returns true on failure it returns an error.
        """
        model_to_load = ReconstructableModel.construct_from_stored_model(filename)

        self._ban_classifier = model_to_load.ban_classifier
        self._training_set._normalisation_data = model_to_load.normalisation_data
        self._training_set._normalisation_function = self._training_set.normalise_individual
        if self._training_set._normalisation_data[TrainingSet.NORMALISATION_TYPE] == 'sparse':
            self._training_set._normalisation_function = self._training_set.normalise_sparse

        return True

    def get_training_model(self):
        """
        Simply an access function for ip_feature_list and target in the training
        set. Objects are not safe to modify, so be nice.
        """
        return (self._training_set._ip_index, \
                    self._training_set._ip_feature_array, \
                    self._training_set._target)
