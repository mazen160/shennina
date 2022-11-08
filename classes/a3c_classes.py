import logging, os
logging.disable(logging.WARNING)
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
from tensorflow.python.keras import layers
from tensorflow.python import keras
import tensorflow as tf
import matplotlib.pyplot as plt
import matplotlib
from queue import Queue
import numpy as np
import multiprocessing
import re
from utils import PPrint
import argparse
import json
import utils
import threading
import time
import sys
import config
import os

os.environ["CUDA_VISIBLE_DEVICES"] = ""
sys.path.append(config.PROJECT_PATH + "/classes/")
import msf_wrapper
import a3c_classes
import scan_cluster
import queue
import service_scan
import generate_exploits_tree
matplotlib.use('PS')
tf.compat.v1.enable_eager_execution()
ST_OS_TYPE = 1    # OS types (unix, linux, windows, osx..).
ST_SERV_NAME = 0  # Product name on Port.
NUM_STATES = 1    # Size of state.
TOTAL_EPS = 1000  # Number of episodes
NUM_WORKERS = 1   # Number of workers
OS_LIST = config.OS_LIST.split("@")
SERVICE_LIST = config.SERVICE_LIST.split("@")
exploits_array = []
global_episode = 0


def build_model(state_size, action_space):
    input_layer = layers.Input(batch_shape=(None, state_size))
    dense_layer1 = layers.Dense(10, activation='relu')(input_layer)
    dense_layer2 = layers.Dense(20, activation='relu')(dense_layer1)
    dense_layer3 = layers.Dense(20, activation='relu')(dense_layer2)
    dense_layer4 = layers.Dense(40, activation='relu')(dense_layer3)
    out_actions = layers.Dense(
        action_space, activation='softmax')(dense_layer4)
    out_value = layers.Dense(1, activation='linear')(dense_layer4)
    model = keras.Model(inputs=[input_layer], outputs=[out_actions, out_value])
    model.make_predict_function()
    return model


def record(episode, episode_reward, worker_idx, global_ep_reward, result_queue, total_loss, num_steps):
    global_ep_reward = episode_reward
    print(
        f"Episode: {episode} | "
        f"Moving Average Reward: {int(global_ep_reward)} | "
        f"Episode Reward: {int(episode_reward)} | "
        f"Loss: {int(total_loss / float(num_steps) * 1000) / 1000} | "
        f"Steps: {num_steps} | "
        f"Worker: {worker_idx}"
    )
    result_queue.put(global_ep_reward)
    return global_ep_reward


class Environment():
    def __init__(self, name):
        self.host = name
        self.state = []

    def normalization(self, target_idx):
        if target_idx == ST_OS_TYPE:
            os_num = int(self.state[ST_OS_TYPE])
            os_num_mean = len(OS_LIST) / 2.0
            self.state[ST_OS_TYPE] = (os_num - os_num_mean) / os_num_mean
        if target_idx == ST_SERV_NAME:
            service_num = self.state[ST_SERV_NAME]
            service_num_mean = len(SERVICE_LIST) / 2.0
            self.state[ST_SERV_NAME] = (
                service_num - service_num_mean) / service_num_mean

    def run_testing_worker(self, input_data, action):
        exploit = utils.get_value(exploits_array, action)
        try:
            test_output = utils.get_exploit_reward(input_data, exploit)
        except:
            test_output = {"host": None}
        if test_output["host"]:
            PPrint().success("Pwned!")
            return test_output
        return None

    def get_state(self, input_data):
        self.state = []
        # Set os type to state.
        # os = input_data["platform"] or ""
        # self.state.insert(ST_OS_TYPE, utils.get_index(OS_LIST, os.lower()))
        # self.normalization(ST_OS_TYPE)
        # Get product name.
        service_name = input_data['name'].replace(" ", "") or ""
        self.state.insert(ST_SERV_NAME, utils.get_index(
            SERVICE_LIST, service_name.lower()))
        # self.normalization(ST_SERV_NAME)
        return np.asarray(self.state)

    def reset(self, details):
        # Initialize state.
        self.state = []
        # os = details['platform'] or ""
        # Set os type to state.
        # self.state.insert(ST_OS_TYPE, utils.get_index(OS_LIST, os.lower()))
        # Get product name.

        # self.normalization(ST_OS_TYPE)
        service_name = details['name'].replace(" ", "")
        self.state.insert(ST_SERV_NAME, utils.get_index(
            SERVICE_LIST, service_name.lower()))
        # self.normalization(ST_SERV_NAME)
        return np.asarray(self.state)

    def step(self, input_data, action):
        result = self.run_testing_worker(input_data, action)
        done = True  # always true.
        if not result:
            reward = -1
        else:
            reward = 1
        state = self.get_state(input_data)
        return state, reward, done


class MasterAgent():
    def __init__(self, host):
        global exploits_array
        self.host = host
        save_dir = "./"
        self.save_dir = save_dir
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)
        env = Environment(host)
        self.state_size = NUM_STATES
        client = config.getClient()
        exploits_array = config.loadExploitsTree(detailed=False)
        self.action_size = len(exploits_array)
        self.opt = tf.keras.optimizers.RMSprop(0.005, .99)
        self.global_model = build_model(
            self.state_size, self.action_size)  # global network
        self.global_model(tf.convert_to_tensor(
            np.random.random((1, self.state_size)), dtype=tf.float32))
        try:
            model_path = os.path.join(self.save_dir, 'pwn_model.h5')
            print('Loading model from: {}'.format(model_path))
            self.global_model.load_weights(model_path)
        except:
            # Doesn't exist
            pass

    def train(self, result):
        global exploits_array
        res_queue = Queue()
        port_groups = utils.generate_chunks(result['ports'], NUM_WORKERS)
        workers = [Worker(self.state_size,
                          self.action_size,
                          self.global_model,
                          self.opt, res_queue,
                          i, host=self.host,
                          save_dir=self.save_dir, result=result, ports=port_group) for i, port_group in enumerate(port_groups)]
        for i, worker in enumerate(workers):
            print("Starting worker {}".format(i))
            worker.start()

        moving_average_rewards = []  # record episode reward to plot
        while True:
            reward = res_queue.get()
            if reward is not None:
                moving_average_rewards.append(reward)
            else:
                break

        [w.join() for w in workers]

        # Saving the model when finally done.
        self.global_model.save_weights(
            os.path.join(self.save_dir,
                         'pwn_model.h5')
        )

    def get_suggested_exploits(self, model, port, result):
        port_exploits = []
        data = result["service_details"][str(port)]
        input_data = {"host": self.host, "port": port,
                      "name": data["name"], "name": data["name"], "version": data["version"], "platform": result["osname"]}
        env = Environment(self.host)
        state = env.reset(input_data)
        reward_sum = 0
        p, _ = model.predict(state)
        prob = []
        for ind in range(len(exploits_array)):
            action = utils.get_value(exploits_array, ind)
            prob.append([action, p[0][ind]])
        prob.sort(key=lambda s: -s[1])
        for i in prob[:20]:
            action = i[0]
            if scan_cluster.post_process_exploit_suggestion(port, result["osname"], data["name"], action):
                port_exploits.append(action)
            if len(port_exploits) >= 4:  # TOP 4 exploits
                break
        return port_exploits

    def play(self, result):
        model = self.global_model
        model_path = os.path.join(self.save_dir, 'pwn_model.h5')
        print('Loading model from: {}'.format(model_path))
        model.load_weights(model_path)
        exploits_list = []
        for port in result["ports"]:
            port_exploits = self.get_suggested_exploits(model, port, result)
            exploits_list.append((port, port_exploits))
        return exploits_list


class Memory:
    def __init__(self):
        self.states = []
        self.actions = []
        self.rewards = []

    def store(self, state, action, reward):
        self.states.append(state)
        self.actions.append(action)
        self.rewards.append(reward)

    def clear(self):
        self.states = []
        self.actions = []
        self.rewards = []


class Worker(threading.Thread):
    # Set up global variables across different threads
    # Moving average reward
    global_moving_average_reward = 0
    best_score = 0
    save_lock = threading.Lock()

    def __init__(self,
                 state_size,
                 action_size,
                 global_model,
                 opt,
                 result_queue,
                 idx,
                 host='',
                 save_dir='./',
                 result={},
                 ports=[]
                 ):
        super(Worker, self).__init__()
        global global_episode
        self.state_size = state_size
        self.action_size = action_size
        self.result_queue = result_queue
        self.global_model = global_model
        self.opt = opt
        self.local_model = build_model(self.state_size, self.action_size)
        self.worker_idx = idx
        self.host = host
        self.env = Environment(self.host)
        self.save_dir = save_dir
        self.ep_loss = 0.0
        self.result = result
        self.input_data = {}
        self.exploits_list = []
        self.ports = ports

    def run(self):
        global global_episode
        while global_episode < TOTAL_EPS:
            for port in self.ports:
                data = self.result["service_details"][str(port)]
                self.exploits_list = data['exploits']
                self.input_data = {"host": self.host, "port": port,
                                   "name": data["name"], "name": data["name"], "version": data["version"], "platform": self.result["osname"]}
                current_state = self.env.reset(self.input_data)
                mem = Memory()
                ep_reward = 0.
                ep_steps = 1
                self.ep_loss = 0
                if len(data['exploits']):
                    action = utils.get_index(
                        exploits_array, np.random.choice(data['exploits']))
                else:
                    logits, _ = self.local_model(tf.convert_to_tensor(
                        current_state[None, :], dtype=tf.float32))
                    probs = tf.nn.softmax(logits)
                    action = np.random.choice(
                        self.action_size, p=probs.numpy()[0])
                new_state, reward, done = self.env.step(
                    self.input_data, action)
                ep_reward += reward
                mem.clear()
                mem.store(current_state, action, reward)
                # Calculate gradient wrt to local model. We do so by tracking the
                # variables involved in computing the loss by using tf.GradientTape
                with tf.GradientTape() as tape:
                    total_loss = self.compute_loss(done,
                                                   new_state,
                                                   mem,
                                                   .99)
                    self.ep_loss += total_loss
                    # Calculate local gradients
                    grads = tape.gradient(
                        total_loss, self.local_model.trainable_weights)
                    # Push local gradients to global model
                self.opt.apply_gradients(zip(grads,
                                             self.global_model.trainable_weights))
                # Update local model with new weights
                self.local_model.set_weights(self.global_model.get_weights())

                mem.clear()

                if reward > 0:
                    global_episode += 1
                    Worker.global_moving_average_reward = \
                        record(global_episode, ep_reward, self.worker_idx,
                               Worker.global_moving_average_reward, self.result_queue,
                               self.ep_loss, ep_steps)
                ep_steps += 1
        self.result_queue.put(None)

    def compute_loss(self,
                     done,
                     new_state,
                     memory,
                     gamma=0.99):

        reward_sum = 0.
        # Get discounted rewards
        discounted_rewards = []
        for reward in memory.rewards[::-1]:  # reverse buffer r
            reward_sum = reward + gamma * reward_sum
            discounted_rewards.append(reward_sum)
        discounted_rewards.reverse()

        logits, values = self.local_model(
            tf.convert_to_tensor(np.vstack(memory.states),
                                 dtype=tf.float32))
        # Get our advantages
        advantage = tf.convert_to_tensor(np.array(discounted_rewards)[:, None],
                                         dtype=tf.float32) - values
        # Value loss
        value_loss = advantage ** 2

        # Calculate our policy loss
        actions_one_hot = tf.one_hot(
            memory.actions, self.action_size, dtype=tf.float32)
        policy = tf.nn.softmax(logits)
        entropy = tf.reduce_sum(policy * tf.math.log(policy + 1e-10), axis=1)
        policy_loss = tf.nn.softmax_cross_entropy_with_logits(
            labels=actions_one_hot, logits=logits)
        total_loss = tf.reduce_mean((value_loss + policy_loss))
        policy_loss *= tf.stop_gradient(advantage)
        policy_loss += 0.01 * entropy
        total_loss = tf.reduce_mean(((0.5 * value_loss) + policy_loss))
        return total_loss
