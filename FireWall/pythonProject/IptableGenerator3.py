import json
import textwrap
from asyncio import sleep

import nltk
import torch

import re
from typing import List, NamedTuple, Optional
from sentence_transformers import SentenceTransformer, util
from nltk.corpus import wordnet
from sklearn.metrics.pairwise import cosine_similarity
import spacy
import socket
import subprocess
import sys


import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import torch
#python -m spacy download en_core_web_lg
nltk.download('wordnet')
class ConnectionInfo(NamedTuple):
    source_ip: Optional[str]
    source_port: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[str]
    protocol: Optional[str]
    single: Optional[bool]


def send_large_data(conn, data):
    CHUNK_SIZE = 1024  # Define your chunk size

    data_length = len(data)
    # Send data in chunks
    for i in range(0, data_length, CHUNK_SIZE):
        conn.sendall(data[i:i + CHUNK_SIZE])
class IptableRuleGenerator:
    def __init__(self, embeddings_file='description_embeddings.pt', rules_file='rules_data.json'):

        self.description_embeddings = torch.load(embeddings_file)
        with open(rules_file, 'r') as f:
            self.rules = json.load(f)
        self.rules_file = rules_file
        with open("iptables2.json", 'r') as f:
            self.iptables_data = json.load(f)
        self.iptables = self.iptables_data
        self.model = SentenceTransformer('all-MiniLM-L6-v2')  # Initialize the model for the message embedding
        self.nlp = spacy.load("en_core_web_lg")
        # Pattern for cases with both source and destination
        self.full_pattern = re.compile(r"""
        (?P<direction1>from|to)            # Capture "from" or "to" as direction1
        (?:\s+\w+)?\s+(?:IP\s)?            # Optionally capture one additional word and then space and optional "IP"
        (?P<ip1>\d{1,3}(?:\.\d{1,3}){3})?   # Capture the first IP address as ip1
        (?:[\s,]*(?:on\s|at\s|through\s|also\s+on\s)?port\s|:\s?)? # Optional first port preamble
        (?P<port1>\d+)?                    # Capture the first port number as port1, if present
        .*?                                # Match any text in between (non-greedy)
        (?P<direction2>from|to)            # Capture "from" or "to" as direction2
        (?:\s+\w+)?\s+(?:IP\s)?            # Optionally capture one additional word and then space and optional "IP"
        (?P<ip2>\d{1,3}(?:\.\d{1,3}){3})?   # Capture the second IP address as ip2
        (?:[\s,]*(?:on\s|at\s|through\s|also\s+on\s)?port\s|:\s?)? # Optional second port preamble
        (?P<port2>\d+)?                    # Capture the second port number as port2, if present
    """, re.VERBOSE | re.DOTALL)

        self.port_only_pattern = re.compile(r"""
            (?P<action>drop|block|reject)\s(?:incoming|outgoing)\s(?:tcp|udp|icmp)\s(?:port\s)?at\s(?P<dst_port>\d+)
        """, re.VERBOSE | re.IGNORECASE)
        self.single_pattern = re.compile(r"""
                   (?P<direction1>from|to)            # Capture "from" or "to" as direction1
                   (?:\s+\w+)?\s+(?:IP\s)?            # Optionally capture one additional word and then space and optional "IP"
                   (?P<ip1>\d{1,3}(?:\.\d{1,3}){3})?   # Capture the first IP address as ip1
                   (?:[\s,]*(?:on\s|at\s|through\s|also\s+on\s)?port\s|:\s?)? # Optional first port preamble
                   (?P<port1>\d+)? """, re.VERBOSE | re.DOTALL)

        self.protocol_pattern = re.compile(r'\b(tcp|udp|icmp)\b', re.IGNORECASE)

    def clean_text(self, text):
        return text.strip().lower()

    def extract_connection_info(self, sentence) -> ConnectionInfo:
        text_value = self.clean_text(sentence)

        src_ip, src_port, dst_ip, dst_port, protocol = None, None, None, None, None
        isSingle = False

        full_match = self.full_pattern.search(sentence)
        if full_match:
            if full_match.group('direction1') == 'from':
                src_ip = full_match.group('ip1')
                src_port = full_match.group('port1')
            elif full_match.group('direction1') == 'to':
                dst_ip = full_match.group('ip1')
                dst_port = full_match.group('port1')

            if full_match.group('direction2') == 'from':
                src_ip = full_match.group('ip2')
                src_port = full_match.group('port2')
            elif full_match.group('direction2') == 'to':
                dst_ip = full_match.group('ip2')
                dst_port = full_match.group('port2')
            isSingle = False
        else:
            single_match = self.single_pattern.search(sentence)
            if single_match:
                if single_match.group('direction1') == 'from':
                    src_ip = single_match.group('ip1')
                    src_port = single_match.group('port1')
                elif single_match.group('direction1') == 'to':
                    dst_ip = single_match.group('ip1')
                    dst_port = single_match.group('port1')
            isSingle = True

        protocol_match = self.protocol_pattern.search(sentence)
        if protocol_match:
            protocol = protocol_match.group(0).lower()


        return ConnectionInfo(
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=protocol,
            single=isSingle
        )

    def get_synonyms(self, word):
        synonyms = set()
        for syn in wordnet.synsets(word):
            for lemma in syn.lemmas():
                synonyms.add(lemma.name().lower())
        return synonyms


    def find_best_match_single(self, input_sentence, protocol=None):

        negative_action_words = {"drop", "block", "deny", "impede"}
        positive_action_words = {"allow", "permit", "authorize", "approve"}

        synonyms = set()
        positive_synonyms = set()

        negative_action_words = {"drop", "block", "deny", "impede"}
        positive_action_words = {"allow", "permit", "authorize", "approve"}

        synonyms = set()
        for word in negative_action_words:
            if word != "reject" or word != "dip" or word != "sip" or word != "sport" or "dport":  # Avoid "reject" since it's handled differently
                synonyms.update(self.get_synonyms(word))

        positive_synonyms = set()
        for word in positive_action_words:
            if word != "dip" or word != "sip" or word != "sport" or "dport":
                positive_synonyms.update(self.get_synonyms(word))

        for synonym in synonyms:
            # Check if the synonym is not one of the excluded words
            if synonym not in ["dip", "sip", "sport", "dport"]:
                message = input_sentence.replace(synonym, "drop")

        for synonym in positive_synonyms:
            # Check if the synonym is not one of the excluded words
            if synonym not in ["dip", "sip", "sport", "dport"]:
                message = input_sentence.replace(synonym, "allow")

        # Encode the normalized input sentence
        input_embedding = self.model.encode(input_sentence, convert_to_tensor=True)

        potential_matches = []

        for item in self.iptables:
            description = item['description'].lower()
            description_embedding = self.model.encode(description, convert_to_tensor=True)
            cosine_similarity_score = util.pytorch_cos_sim(input_embedding, description_embedding).item()
            similarity_score = util.pytorch_cos_sim(input_embedding, description_embedding).item()
            exact_match_score = 0
            if "from" in description and "to" in description:
                continue
            if "icmp" in description and "ICMP" in input_sentence:
                has_sip = "{sip}" in description and "from" in input_sentence
                if has_sip:
                    exact_match_score += 2
                if "icmp" in description and "icmp" in input_sentence:
                    exact_match_score += 8
            elif ("TCP" in input_sentence and "tcp" in description) or ("UDP" in input_sentence and "udp" in description):

                if ("dip" in input_sentence
                        and "dport" in input_sentence
                        and not "sport" in input_sentence
                        and not "sip" in input_sentence):
                    if ("dip" in description
                            and "dport" in description
                            and not "sport" in description
                            and not "sip" in description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score + 4
                        potential_matches.append((item, combined_score))
                        continue

                if ("dip" in input_sentence
                        and not "sip" in input_sentence
                        and not "dport" in description):
                    if ("dip" in description
                            and not "sip" in description
                            and not "dport" in description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((item, combined_score))
                        continue
                if ("dport" in input_sentence
                        and not "sport" in input_sentence
                        and not "sip" in input_sentence):
                    if ("dip" in description
                            and not "sport" in description
                            and not "sip" in description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((item, combined_score))
                        continue
                if ("sip" in input_sentence
                        and "sport" in input_sentence
                        and not "dport" in input_sentence
                        and not "dip" in input_sentence):
                    if ("sip" in description
                            and "sport" in description
                            and not "dport" in description
                            and not "dip" in description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score + 4
                        potential_matches.append((item, combined_score))
                        continue

                if ("sip" in input_sentence
                        and not "dip" in input_sentence
                        and not "sport" in description):
                    if ("sip" in description
                            and not "dip" in description
                            and not "sport" in description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((item, combined_score))
                        continue
                if ("sport" in input_sentence
                        and not "dport" in input_sentence
                        and not "dip" in input_sentence):
                    if ("sport" in description
                            and not "dport" in description
                            and not "dip" in description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((item, combined_score))
                        continue


                if "allow" in description and "allow" in input_sentence:
                    exact_match_score += 4
                if "drop" in description and "drop" in input_sentence:
                    exact_match_score += 2
                if "reject" in description and "reject" in input_sentence:
                    exact_match_score += 2

                if "to" in description and "to" in input_sentence:
                    exact_match_score += 2
                if "from" in description and "from" in input_sentence:
                    exact_match_score += 2
                if "on port" in description and "on port" in input_sentence:
                    exact_match_score += 2
                if "{sip}" in description and "{sip}" in input_sentence:
                    exact_match_score += 2
                if "{sport}" in description and "{sport}" in input_sentence:
                    exact_match_score += 2
                if "{sport}" in description and "{sport}" in input_sentence and not "{sip}" in description and not "{sip}" in input_sentence:
                    exact_match_score += 4
                if "{dip}" in description and "{dip}" in input_sentence:
                    exact_match_score += 2
                if "{dport}" in description and "{dport}" in input_sentence:
                    exact_match_score += 2
                if "{dport}" in description and "{dport}" in input_sentence and not "{dip}" in description and not "{dip}" in input_sentence:
                    exact_match_score += 4


            combined_score = exact_match_score * 2 + similarity_score
            potential_matches.append((item, combined_score))

        potential_matches.sort(key=lambda x: x[1], reverse=True)
        print(input_sentence)
        for i, (item, score) in enumerate(potential_matches[:10]):  # Print top 5 matches
            print(f"Match {i + 1}: Description: {item['description']}, Score: {score}")


        if potential_matches and potential_matches[0][1] > 0.65:
            top_matches = potential_matches[:15]

            best_match = None
            highest_match_score = -1

            for match in top_matches:
                rule_description = match[0]['description'].lower()
                match_score = 0

                # Skip rule descriptions containing both "from" and "to"
                if "from" in rule_description and "to" in rule_description:
                    continue
                elif "ICMP" in rule_description:
                    has_sip = "{sip}" in rule_description and "from" in input_sentence
                    if has_sip:
                        match_score += 2
                    if "ICMP" in rule_description and "ICMP" in input_sentence:
                        match_score += 2
                elif "TCP" in rule_description and "UDP" in rule_description:
                    if ("dip" in input_sentence
                            and "dport" in input_sentence
                            and not "sport" in input_sentence
                            and not "sip" in input_sentence):
                        if ("dip" in rule_description
                                and "dport" in rule_description
                                and not "sport" in rule_description
                                and not "sip" in rule_description):
                            match_score += 10


                    if ("dip" in input_sentence
                            and not "sip" in input_sentence
                            and not "dport" in description):
                        if ("dip" in rule_description
                                and not "sip" in rule_description
                                and not "dport" in rule_description):
                            match_score += 10

                    if ("dport" in input_sentence
                            and not "sport" in input_sentence
                            and not "sip" in input_sentence):
                        if ("dip" in rule_description
                                and not "sport" in rule_description
                                and not "sip" in rule_description):
                            match_score += 10

                    if ("sip" in input_sentence
                            and "sport" in input_sentence
                            and not "dport" in input_sentence
                            and not "dip" in input_sentence):
                        if ("sip" in description
                                and "sport" in rule_description
                                and not "dport" in rule_description
                                and not "dip" in rule_description):
                            match_score += 10


                    if ("sip" in input_sentence
                            and not "dip" in input_sentence
                            and not "sport" in description):
                        if ("sip" in description
                                and not "dip" in rule_description
                                and not "sport" in rule_description):
                            match_score += 10
                    if ("sport" in input_sentence
                            and not "dport" in input_sentence
                            and not "dip" in input_sentence):
                        if ("sport" in description
                                and not "dport" in rule_description
                                and not "dip" in rule_description):
                            match_score += 10

                # Check for presence of various parameters in the rule description and input sentence
                    has_sip = "{sip}" in rule_description and "from" in input_sentence
                    has_dip = "{dip}" in rule_description and "to" in input_sentence
                    has_sport = "{sport}" in rule_description and "sport" in input_sentence
                    has_dport = "{dport}" in rule_description and "dport" in input_sentence
                    has_protocol = "{protocol}" in rule_description and "protocol" in input_sentence

                    # Score calculation based on presence of parameters
                    if has_sip:
                        match_score += 2
                    if has_dip:
                        match_score += 2
                    if has_sport:
                        match_score += 2
                    if has_dport:
                        match_score += 2
                    if "{sport}" in rule_description and "{sport}" in input_sentence and not "{sip}" in rule_description and not "{sip}" in input_sentence:
                        match_score += 4
                    if "{dport}" in rule_description and "{dport}" in input_sentence and not "{dip}" in rule_description and not "{dip}" in input_sentence:
                        match_score += 4

                    if has_protocol:
                        match_score += 2
                    if "allow" in input_sentence and "allow" in rule_description:
                        match_score += 4
                    if "drop" in input_sentence and "drop" in rule_description:
                        match_score += 2
                    if "reject" in input_sentence and "reject" in rule_description:
                        match_score += 2

                # Update the best match if current match score is higher
                if match_score > highest_match_score:
                    best_match = match[0]['iptables_commands']
                    highest_match_score = match_score*1.3
                    print(match[0]["description"])
            return best_match
        else:
            return "Not found"

    def find_best_match(self, message, protocol=None):
        message = message.lower()

        # Step 1: Define negative and positive action words with synonyms
        negative_action_words = {"drop", "block", "deny", "impede"}
        positive_action_words = {"allow", "permit", "authorize", "approve"}

        synonyms = set()
        for word in negative_action_words:
            if word != "reject" or word != "dip" or word != "sip" or word != "sport" or "dport":  # Avoid "reject" since it's handled differently
                synonyms.update(self.get_synonyms(word))

        positive_synonyms = set()
        for word in positive_action_words:
            if word != "dip" or word != "sip" or word != "sport" or "dport":
                positive_synonyms.update(self.get_synonyms(word))

        for synonym in synonyms:
            # Check if the synonym is not one of the excluded words
            if synonym not in ["dip", "sip", "sport", "dport"]:
                message = message.replace(synonym, "drop")

        for synonym in positive_synonyms:
            # Check if the synonym is not one of the excluded words
            if synonym not in ["dip", "sip", "sport", "dport"]:
                message = message.replace(synonym, "allow")

        potential_matches = []
        input_embedding = self.model.encode(message, convert_to_tensor=True)

        # Step 3: Iterate through rules and calculate initial similarity and exact match scores
        for rule in self.rules:
            rule_description = rule['description'].lower()
            if "from" in rule_description and "to" in rule_description:

                rule_embedding = self.model.encode(rule_description, convert_to_tensor=True)
                message_embedding = self.model.encode(message, convert_to_tensor=True)
                similarity_score = util.pytorch_cos_sim(message_embedding, rule_embedding).item()
                description_embedding = self.model.encode(rule_description, convert_to_tensor=True)
                message_embedding_score = util.pytorch_cos_sim(input_embedding, description_embedding).item()
                # Calculate exact match score
                exact_match_score = 0

                if ("sip" in message
                    and "dip" in message
                    and "sport" in message
                    and "dport" in message):
                        if ("sip" in rule_description
                            and "dip" in rule_description
                            and "sport" in rule_description
                            and "dport" in rule_description):

                            exact_match_score += 10
                            combined_score = exact_match_score * 2 + similarity_score
                            potential_matches.append((rule['description'], combined_score))
                            continue
                if ("sip" in message
                        and "dip" in message
                        and "dport" in message):
                    if ("sip" in rule_description
                            and "dip" in rule_description
                            and not "sport" in rule_description
                            and "dport" in rule_description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule['description'], combined_score))
                        continue
                if ("sip" in message
                        and "dip" in message
                        and "sport" in message):
                    if ("sip" in rule_description
                            and "dip" in rule_description
                            and "sport" in rule_description
                            and not "dport" in rule_description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule['description'], combined_score))
                        continue
                if ("sip" in message
                    and "dport" in message):
                        if ("sip" in rule_description
                            and not "dip" in rule_description
                            and not "sport" in rule_description
                            and "dport" in rule_description):
                            exact_match_score += 10
                            combined_score = exact_match_score * 2 + similarity_score
                            potential_matches.append((rule['description'], combined_score))
                            continue
                if ("sip" in message
                        and "sport" in message
                        and "dport" in message):
                    if ("sip" in rule_description
                            and not "dip" in rule_description
                            and "sport" in rule_description
                            and "dport" in rule_description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule['description'], combined_score))
                        continue
                if ("dip" in message
                        and "sport" in message):
                    if ("dip" in rule_description
                            and "sport" in rule_description
                            and not "sip" in rule_description
                            and not "dport" in rule_description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule['description'], combined_score))
                        continue
                if ("dip" in message
                        and "sport" in message
                        and "dport" in message):
                    if ("dip" in rule_description
                            and not "sip" in rule_description
                            and "sport" in rule_description
                            and "dport" in rule_description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule['description'], combined_score))
                        continue
                if ("sip" in message
                        and "dip" in message):
                    if ("sip" in rule_description
                            and "dip" in rule_description
                            and not "sport" in rule_description
                            and not "dport" in rule_description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule['description'], combined_score))
                        continue
                if ("sport" in message
                        and "dport" in message):
                        if ("sport" in rule_description
                            and "dport" in rule_description
                                and not "sip" in rule_description
                                and not "dip" in rule_description):
                            exact_match_score += 10
                            combined_score = exact_match_score * 2 + similarity_score
                            potential_matches.append((rule['description'], combined_score))
                            continue
                if ("sip" in message
                        and "dport" in message):
                    if ("sip" in rule_description
                            and "dport" in rule_description
                            and not "dip" in rule_description
                            and not "sport" in rule_description):

                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule['description'], combined_score))
                        continue
                if ("dip" in message
                        and "sport" in message):
                    if ("dip" in rule_description
                            and "sport" in rule_description
                            and not "sip" in rule_description
                            and not "dport" in rule_description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule['description'], combined_score))
                        continue


                if "{sip}" in rule_description and "from" in message:
                    exact_match_score += 1
                if "{dip}" in rule_description and "to" in message:
                    exact_match_score += 1

                if "{sport}" in rule_description and "sport" in message:
                    exact_match_score += 1
                if "{dport}" in rule_description and "dport" in message:
                    exact_match_score += 1
                if "{sport}" in rule_description and "{sport}" in message and not "{sip}" in rule_description and not "{sip}" in message:
                    exact_match_score += 1
                if "{dport}" in rule_description and "{dport}" in message and not "{dip}" in rule_description and not "{dip}" in message:
                    exact_match_score += 1
                if "{sport}" in rule_description and "{sport}" in message and not "{dport}" in rule_description and not "{dport}" in message:
                    exact_match_score += 1
                if "{dport}" in rule_description and "{dport}" in message and not "{sport}" in rule_description and not "{sport}" in message:
                    exact_match_score += 1
                if "{dport}" in rule_description and "{dport}" in message and "{sport}" in rule_description and "{sport}" in message \
                    and not "{sip}" in rule_description and not "{sip}" in message and not "{dip}" in rule_description and not "{dip}" in message:
                    exact_match_score += 1
                if "allow" in rule_description and "allow" in message:
                    exact_match_score += 2
                if "drop" in rule_description and "drop" in message:
                    exact_match_score += 2
                if "reject" in rule_description and "reject" in message:
                    exact_match_score += 2
                # if "{protocol}" in rule_description and "{protocol}" in message:
                #     exact_match_score += 1

                combined_score = exact_match_score * 2 + similarity_score + message_embedding_score

                potential_matches.append((rule['description'], combined_score))
        return potential_matches


    def find_or_generate_rule(self, sentences: List[str]):
        print("=======================started===============")
        results = []
        for sentence in sentences:
            print("\nBefore processed:", sentence)
            match = self.full_pattern.search(sentence)

            info = self.extract_connection_info(sentence)
            message = sentence
            if info.source_ip:
                message = message.replace(info.source_ip, "{sip}")
            if info.source_port:
                message = message.replace(info.source_port, "{sport}")
            if info.destination_ip:
                message = message.replace(info.destination_ip, "{dip}")
            if info.destination_port:
                message = message.replace(info.destination_port, "{dport}")
            if info.protocol:
                message = message.replace(info.protocol, "{protocol}")

            print("Processed message:", message)
            if(info.single == False):
                best_result = self.find_best_match(message, protocol=info.protocol)
            else:
                best_result = self.find_best_match_single(message, protocol=info.protocol)
            self.plot_attention_graph(best_result)



    def parse_iptables_response(self, iptables_response = None):
        # Split the iptables response into different chains
        lines = iptables_response.splitlines()
        chains = {}
        current_chain = None

        for line in lines:
            if line.startswith("Chain"):
                # Identify a new chain
                current_chain = line.strip()
                chains[current_chain] = []
            elif current_chain:
                # Add the relevant information under the current chain
                chains[current_chain].append(line.strip())

        # Format the result into JSON format
        formatted_data = {}
        for chain, details in chains.items():
            chain_key = chain.split()[1]  # extracting the chain name as the key
            formatted_data[chain_key] = {
                "columns": ["pkts", "bytes", "target", "prot", "opt", "in", "out", "source", "destination"],
                "entries": details
            }

        return json.dumps(formatted_data)


    def plot_attention_graph(self, potential_matches):
        potential_matches_sorted = sorted(potential_matches, key=lambda x: x[1], reverse=True)

        # Extract the top 15 matches
        top_matches = potential_matches_sorted[:15]

        # Extract rule descriptions and scores for the top 15 matches
        rule_descriptions = [rule[0] for rule in top_matches]
        scores = [rule[1] for rule in top_matches]

        # Wrapping the descriptions for better readability in the heatmap
        wrapped_rule_descriptions = ['\n'.join(textwrap.wrap(desc, 40)) for desc in
                                     rule_descriptions]  # Adjust 40 as needed

        # Plot the heatmap with the top 15 matches
        plt.figure(figsize=(10, 8))  # Adjusted to make the table smaller while handling long descriptions
        # Format the scores to display float numbers with two decimal places
        formatted_scores = np.array([f"{score:.2f}" for score in scores]).reshape(-1, 1)

        # Use sns.heatmap and reduce the fontsize for yticklabels to "zoom out"
        sns.heatmap(np.array(scores).reshape(-1, 1), annot=formatted_scores, fmt="", cmap='Blues',
                    yticklabels=wrapped_rule_descriptions,
                    xticklabels=['Message'], cbar=False, annot_kws={"size": 8})

        # Set font sizes for a compact view while handling long text
        plt.yticks(fontsize=8)  # Smaller y-axis labels to fit the wrapped text
        plt.xticks(fontsize=10)  # X-axis font size
        plt.title("Attention Graph: Top 15 Combined Scores", fontsize=12)
        plt.xlabel("Message", fontsize=10)
        plt.ylabel("Top 15 Rules", fontsize=10)

        plt.tight_layout()  # Ensure the layout fits within the figure area
        plt.show()
def iptableGeneratorTest():
    TCP1 = [
        "drop from 192.168.0.12 on port 5555 to 192.168.0.13 on port 5555 using TCP.",
    ]

    generator = IptableRuleGenerator()
    count = 0
    result = []

    result = generator.find_or_generate_rule(TCP1)




# Example usage:
if __name__ == "__main__":

    iptableGeneratorTest();


