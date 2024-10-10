import json
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
        self.nlp = spacy.load("en_core_web_lg")
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
                            potential_matches.append((rule, combined_score))
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
                        potential_matches.append((rule, combined_score))
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
                        potential_matches.append((rule, combined_score))
                        continue
                if ("sip" in message
                    and "dport" in message):
                        if ("sip" in rule_description
                            and not "dip" in rule_description
                            and not "sport" in rule_description
                            and "dport" in rule_description):
                            exact_match_score += 10
                            combined_score = exact_match_score * 2 + similarity_score
                            potential_matches.append((rule, combined_score))
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
                        potential_matches.append((rule, combined_score))
                        continue
                if ("dip" in message
                        and "sport" in message):
                    if ("dip" in rule_description
                            and "sport" in rule_description
                            and not "sip" in rule_description
                            and not "dport" in rule_description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule, combined_score))
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
                        potential_matches.append((rule, combined_score))
                        continue
                if ("sip" in message
                        and "dip" in message):
                    if ("sip" in rule_description
                            and "dip" in rule_description
                            and not "sport" in rule_description
                            and not "dport" in rule_description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule, combined_score))
                        continue
                if ("sport" in message
                        and "dport" in message):
                        if ("sport" in rule_description
                            and "dport" in rule_description
                                and not "sip" in rule_description
                                and not "dip" in rule_description):
                            exact_match_score += 10
                            combined_score = exact_match_score * 2 + similarity_score
                            potential_matches.append((rule, combined_score))
                            continue
                if ("sip" in message
                        and "dport" in message):
                    if ("sip" in rule_description
                            and "dport" in rule_description
                            and not "dip" in rule_description
                            and not "sport" in rule_description):

                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule, combined_score))
                        continue
                if ("dip" in message
                        and "sport" in message):
                    if ("dip" in rule_description
                            and "sport" in rule_description
                            and not "sip" in rule_description
                            and not "dport" in rule_description):
                        exact_match_score += 10
                        combined_score = exact_match_score * 2 + similarity_score
                        potential_matches.append((rule, combined_score))
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
                potential_matches.append((rule, combined_score))

        # Step 4: Sort matches by initial combined score and keep the top 15
        potential_matches.sort(key=lambda x: x[1], reverse=True)
        for i, (item, score) in enumerate(potential_matches[:10]):  # Print top 5 matches
            print(f"Match {i + 1}: Description: {item['description']}, Score: {score}")
        top_matches = potential_matches[:15]

        best_match = None
        highest_match_score = -1
        if top_matches and top_matches[0][1] > 0.55:
            for match in top_matches:
                rule = match[0]
                rule_description = rule['description'].lower()
                match_score = 0
                if ("sip" in message
                    and "dip" in message
                    and "sport" in message
                    and "dport" in message):
                        if ("sip" in rule_description
                            and "dip" in rule_description
                            and "sport" in rule_description
                            and "dport" in rule_description):

                            match_score += 10

                if ("sip" in message
                        and "dip" in message
                        and "dport" in message):
                    if ("sip" in rule_description
                            and "dip" in rule_description
                            and not "sport" in rule_description
                            and "dport" in rule_description):
                        match_score += 10

                if ("sip" in message
                    and "dport" in message):
                        if ("sip" in rule_description
                            and not "dip" in rule_description
                            and not "sport" in rule_description
                            and "dport" in rule_description):
                            match_score += 10

                if ("sip" in message
                        and "sport" in message
                        and "dport" in message):
                    if ("sip" in rule_description
                            and not "dip" in rule_description
                            and "sport" in rule_description
                            and "dport" in rule_description):
                        match_score += 10

                if ("dip" in message
                        and "sport" in message):
                    if ("dip" in rule_description
                            and "sport" in rule_description
                            and not "sip" in rule_description
                            and not "dport" in rule_description):
                        match_score += 10

                if ("dip" in message
                        and "sport" in message
                        and "dport" in message):
                    if ("dip" in rule_description
                            and not "sip" in rule_description
                            and "sport" in rule_description
                            and "dport" in rule_description):
                        match_score += 10

                if ("sip" in message
                        and "dip" in message):
                    if ("sip" in rule_description
                            and "dip" in rule_description
                            and not "sport" in rule_description
                            and not "dport" in rule_description):
                        match_score += 10

                if ("sport" in message
                        and "dport" in message):
                        if ("sport" in rule_description
                            and "dport" in rule_description
                                and not "sip" in rule_description
                                and not "dip" in rule_description):
                            match_score += 10

                if ("sip" in message
                        and "dport" in message):
                    if ("sip" in rule_description
                            and "dport" in rule_description
                            and not "dip" in rule_description
                            and not "sport" in rule_description):

                        match_score += 10

                if ("dip" in message
                        and "sport" in message):
                    if ("dip" in rule_description
                            and "sport" in rule_description
                            and not "sip" in rule_description
                            and not "dport" in rule_description):
                        match_score += 10

                # has_sip = "{sip}" in rule_description and "{sip}" in message
                # has_dip = "{dip}" in rule_description and "{dip}" in message
                # has_sport = "{sport}" in rule_description and "{sport}" in message
                # has_dport = "{dport}" in rule_description and "{dport}" in message
                # has_protocol = ("{protocol}" in rule_description and
                #                 (("TCP" in rule["iptables_commands"]) or
                #                  ("UDP" in rule["iptables_commands"]) or
                #                  ("ICMP" in rule["iptables_commands"])))
                #
                # if has_sip:
                #     match_score += 2
                # if has_dip:
                #     match_score += 2
                # if has_sport:
                #     match_score += 2
                # if has_dport:
                #     match_score += 2
                # if has_protocol:
                #     match_score += 2
                # if "{sip}" in rule_description and "{sip}" in message and "{dip}" in rule_description and "{dip}" in message \
                #         and  "{sport}" in rule_description and "{sport}" in message \
                #         and "{dport}" in rule_description and "{dport}" in message:
                #     match_score += 4.5
                # if "{sport}" in rule_description and "{sport}" in message and not "{sip}" in rule_description and not "{sip}" in message:
                #     match_score += 2
                # if "{dport}" in rule_description and "{dport}" in message and not "{dip}" in rule_description and not "{dip}" in message:
                #     match_score += 2
                if "allow" in rule_description and "ACCEPT" in rule["iptables_commands"]:
                    match_score += 2
                if "drop" in rule_description and "DROP" in rule["iptables_commands"]:
                    match_score += 2
                if "reject" in rule_description and "REJECT" in rule["iptables_commands"]:
                    match_score += 2



                if match_score > highest_match_score:
                    best_match = rule['iptables_commands']
                    highest_match_score = match_score
                return best_match
        else:
            return "Not found"

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

            if best_result != "Not found":
                if info.source_ip:
                    best_result = [cmd.replace("{sip}", info.source_ip) for cmd in best_result]
                if info.source_port:
                    best_result = [cmd.replace("{sport}", info.source_port) for cmd in best_result]
                if info.destination_ip:
                    best_result = [cmd.replace("{dip}", info.destination_ip) for cmd in best_result]
                if info.destination_port:
                    best_result = [cmd.replace("{dport}", info.destination_port) for cmd in best_result]
                if info.protocol:
                    best_result = [cmd.replace("{protocol}", info.protocol.lower()) for cmd in best_result]

                print("Fully Generated iptables rule:", best_result)
            results.append(best_result)
        return results


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
    def get_private_ip(self):
        try:
            # Create a UDP socket and connect to a non-existent IP just to get the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))  # Google's public DNS server
            ip_address = s.getsockname()[0]  # Get the IP address of the local machine
        except Exception as e:
            print(f"Error: {e}")
            ip_address = '127.0.0.1'  # Return localhost if error occurs
        finally:
            s.close()

        return ip_address

def iptableGeneratorTest(index):
    TCP = [
        "drop from 192.168.0.12 on port 5555 to 192.168.0.13 using TCP.",
        "allow from 192.168.0.12 on port 5555 to 192.168.0.13 using TCP.",
        "reject from 192.168.0.12 on port 5555 to 192.168.0.13 using TCP.",
        "drop from 192.168.0.12 on port 5555 to on port 1234 using TCP.",
        "allow from 192.168.0.12 on port 5555 to on port 1234 using TCP.",
        "reject from 192.168.0.12 on port 5555 to on port 1234 using TCP.",
        "allow from 192.168.0.12 on port 5555 to 192.168.0.13 on port 1234 using TCP.",
        "drop from 192.168.0.12 on port 5555 to 192.168.0.13 on port 1234 using TCP.",
        "reject from 192.168.0.12 on port 5555 to 192.168.0.13 on port 1234 using TCP.",
        "allow from on port 5555 to 192.168.0.13 on port 1234 using TCP.",
        "drop from on port 5555 to 192.168.0.13 on port 1234 using TCP.",
        "reject from on port 5555 to 192.168.0.13 on port 1234 using TCP.",
        "allow from on port 5555 to on port 1234 using TCP.",
        "drop from on port 5555 to on port 1234 using TCP.",
        "reject from on port 5555 to on port 1234 using TCP.",
        "reject from on port 5555 to 192.168.0.12 using TCP.",
        "allow from on port 5555 to 192.168.0.12 using TCP.",
        "drop from on port 5555 tto 192.168.0.12 using TCP.",
        "drop from  192.168.0.12 on port 5555 using TCP.",
        "allow from  192.168.0.12 on port 5555 using TCP.",
        "reject from  192.168.0.12 on port 5555 using TCP.",
        "drop from  192.168.0.12 using TCP.",
        "allow from  192.168.0.12 using TCP.",
        "reject from  192.168.0.12 using TCP.",
    ]
    TCP_reverse = [
        "drop to on port 5555 from  192.168.0.13 using TCP.",
        "allow to on port 5555 from  192.168.0.13 using TCP.",
        "reject to on port 5555 from  192.168.0.13 using TCP.",
        "drop to on port 5555 from on port 1234 using TCP.",
        "allow to on port 5555 from on port 1234 using TCP.",
        "reject to on port 5555 from on port 1234 using TCP.",
        "drop to  192.168.0.12 on port 5555 from on port 1234 using TCP.",
        "allow to  192.168.0.12 on port 5555 from on port 1234 using TCP.",
        "reject to  192.168.0.12 on port 5555 from on port 1234 using TCP.",
        "drop to  192.168.0.12 on port 5555 from  192.168.0.13 on port 1234 using TCP.",
        "allow to  192.168.0.12 on port 5555 from  192.168.0.13 on port 1234 using TCP.",
        "reject to  192.168.0.12 on port 5555 from  192.168.0.13 on port 1234 using TCP.",
        "drop to  192.168.0.12 from  192.168.0.13 on port 1234 using TCP.",
        "allow to  192.168.0.12 from  192.168.0.13 on port 1234 using TCP.",
        "reject to  192.168.0.12 from  192.168.0.13 on port 1234 using TCP.",
        "drop to  192.168.0.12 from  192.168.0.13 using TCP.",
        "allow to  192.168.0.12 from  192.168.0.13 using TCP.",
        "reject to  192.168.0.12 from  192.168.0.13 using TCP.",
        "drop to 192.168.0.12 on port 5555 using TCP.",
        "allow to 192.168.0.12 on port 5555 using TCP.",
        "reject to 192.168.0.12 on port 5555 using TCP.",
        "drop to 192.168.0.12 using TCP.",
        "allow to 192.168.0.12 using TCP.",
        "reject to 192.168.0.12 using TCP.",
        "drop to on port 5555 using TCP.",
        "allow to on port 5555 using TCP.",
        "reject to on port 5555 using TCP.",
    ]


    UDP = [
        "drop from  192.168.0.12 on port 5555 to  192.168.0.13 on port 1234 using UDP.",
        "allow from  192.168.0.12 on port 5555 to  192.168.0.13 on port 1234 using UDP.",
        "reject from  192.168.0.12 on port 5555 to  192.168.0.13 on port 1234 using UDP.",
        "drop from  192.168.0.12 to  192.168.0.13 on port 5555 using UDP.",
        "allow from  192.168.0.12 to  192.168.0.13 on port 5555 using UDP.",
        "reject from  192.168.0.12  to  192.168.0.13  on port 5555 using UDP.",
        "drop from  192.168.0.12 on port 5555 using UDP.",
        "allow from  192.168.0.12 on port 5555 using UDP.",
        "reject from  192.168.0.12 on port 5555 using UDP.",
        "drop from  192.168.0.12 to  192.168.0.13 using UDP.",
        "allow from  192.168.0.12 to  192.168.0.13 using UDP.",
        "reject from  192.168.0.12  to  192.168.0.13 using UDP.",
        "drop from  192.168.0.12 using UDP.",
        "allow from  192.168.0.12 using UDP.",
        "reject from  192.168.0.12 using UDP.",
        "drop from on port 5555 to  192.168.0.13 on port 1234 using UDP.",
        "allow from on port 5555 to  192.168.0.13 on port 1234 using UDP.",
        "reject from on port 5555 to  192.168.0.13 on port 1234 using UDP.",
        "drop from on port 5555 to  192.168.0.13 using UDP.",
        "allow from on port 5555 to  192.168.0.13 using UDP.",
        "reject from on port 5555 to  192.168.0.13 using UDP.",
        "drop from on port 5555 to on port 1234 using UDP.",
        "allow from on port 5555 to on port 1234 using UDP.",
        "reject from on port 5555 to on port 1234 using UDP.",
        "drop from on port 5555 using UDP.",
        "allow from on port 5555 using UDP.",
        "reject from on port 5555 using UDP.",
    ]

    UDP_reverse = [
        "drop to  192.168.0.12 on port 5555 from  192.168.0.13 on port 1234 using UDP.",
        "allow to  192.168.0.12 on port 5555 from  192.168.0.13 on port 1234 using UDP.",
        "reject to  192.168.0.12 on port 5555 from  192.168.0.13 on port 1234 using UDP.",
        "drop to on port 5555 from on port 1234 using UDP.",
        "allow to on port 5555 from on port 1234 using UDP.",
        "reject to on port 5555 from on port 1234 using UDP.",
        "drop to  on port 5555 from on port 1234 using UDP.",
        "allow to  192.168.0.12 on port 5555 from  192.168.0.13 using UDP.",
        "reject to  192.168.0.12 on port 5555 from  192.168.0.13 using UDP.",
        "drop to on port 5555 from  192.168.0.13 using UDP.",
        "allow to on port 5555 from  192.168.0.13 using UDP.",
        "reject to on port 5555 from  192.168.0.13 using UDP.",
        "drop to 192.168.0.12 from  192.168.0.13 using UDP.",
        "allow to  192.168.0.12 from  192.168.0.13 using UDP.",
        "reject to  192.168.0.12 from  192.168.0.13 using UDP.",
        "drop to  192.168.0.12 on port 5555 using UDP.",
        "allow to  192.168.0.12 on port 5555 using UDP.",
        "reject to  192.168.0.12 on port 5555 using UDP.",
        "drop to  192.168.0.12 using UDP.",
        "allow to  192.168.0.12 using UDP.",
        "reject to  192.168.0.12 using UDP.",
        "drop to on port 5555 using UDP.",
        "allow to on port 5555 using UDP.",
        "reject to on port 5555 using UDP.",
    ]

    ICMP = [
        "drop from  192.168.0.12 using ICMP.",
        "allow from  192.168.0.12 using ICMP.",
        "reject from  192.168.0.12 using ICMP.",
        "drop limited Echo Requests using ICMP",
        "allow limited Echo Requests using ICMP",
        "reject limited Echo Requests using ICMP",
        "drop limited traffic using ICMP",
        "allow limited traffic using ICMP",
        "reject limited traffic using ICMP"
    ]
    TEST = [
        "allow Established and Related Incoming Connections from 192.168.0.12",
        "drop Established and Related Incoming Connections from 192.168.0.12",
        "reject Established and Related Incoming Connections from 192.168.0.12",

    ]
    all_test = [TCP,  UDP, ICMP]
    labels = ["TCP", "TCP_Reverse", "UDP", "UDP_Reverse", "ICMP", "TEST"]
    generator = IptableRuleGenerator()
    count = 0
    result = []

    result = generator.find_or_generate_rule(all_test[index])
    failure_count = 0
    success_count = 0

    index = 0

    for cmd in result:
        try:
            # Flush all the existing rules
            flush_command = 'echo user | sudo -S iptables -F'
            print(f"Executing: {flush_command}")
            subprocess.run(flush_command, shell=True, check=True)
            print("Flushed existing iptables rules.")

            cmd = str(cmd)
            cmd = cmd.strip("[]'")
            full_command = f'echo user | sudo -S {cmd}'
            print(f"Successfully Executed at {index}: {full_command}")
            subprocess.run(full_command, shell=True, check=True)
            success_count += 1
            index += 1
        except subprocess.CalledProcessError as e:
            print(f"Failed to apply rule at {index}: {cmd}. Error: {e}")
            failure_count += 1
            index += 1
    count += 1
    total_count = success_count + failure_count
    success_rate = 0
    failure_rate = 0
    if total_count > 0:
        success_rate = (success_count / total_count) * 100
        failure_rate = (failure_count / total_count) * 100
    else:
        success_rate = 0
        failure_rate = 0
    summary = f'{labels} success: {success_count} / {total_count}   failure: {failure_count} / {total_count}\n'
    result.append(summary)
    print(summary)

def startWebSocket():
    generator = IptableRuleGenerator()
    host = generator.get_private_ip()
    # host = '127.0.0.1'# The server's hostname or IP address
    port = 65432

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse
            s.bind((host, port))
            s.listen()
            print(f"Python server listening on {host}:{port}")

            while True:
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by {addr}")
                    data = conn.recv(2048)
                    if not data:
                        break

                    received_message = data.decode()
                    print(received_message)
                    parsed_data = json.loads(received_message)
                    print("Parsed JSON:", parsed_data)
                    message_value = None
                    # Check if 'message' key exists in the parsed JSON
                    if "message" in parsed_data:
                        message_value = parsed_data["message"]
                        print(f"Extracted message from JSON: {message_value}")
                    else:
                        print("JSON does not contain 'message' key")
                    if message_value == "table":
                        full_command = 'echo user | sudo -S iptables -L -n -v'

                        # Run the command
                        result = subprocess.run(
                            full_command, shell=True, check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True
                        )

                        # Capture the output
                        iptables_response = result.stdout if result.stdout else result.stderr
                        if result.returncode == 0:
                            json_response = generator.parse_iptables_response(iptables_response)
                            print(json_response)
                            send_large_data(conn, json_response.encode())

                    else:
                        # Send the extracted message to the generator
                        result = generator.find_or_generate_rule([message_value])
                        print(f"Received from C++ server:")
                        print(result)
                        flattened_result = [cmd for sublist in result for cmd in sublist]
                        iptables_response = "\n".join(flattened_result)

                        print(f"Formatted iptables rules to send back: {iptables_response}")

                        conn.sendall(iptables_response.encode())
                        print(f"Sent back to C++ server: {iptables_response}")
                        try:
                            for cmd_list in result:
                                for cmd in cmd_list:
                                    try:
                                        full_command = f'echo user | sudo -S {cmd}'
                                        print(f"Executing: {full_command}")
                                        subprocess.run(full_command, shell=True, check=True)
                                        print(f"Successfully applied rule: {cmd}")
                                    except subprocess.CalledProcessError as e:
                                        print(f"Failed to apply rule: {cmd}. Error: {e}")

                        except subprocess.CalledProcessError as e:
                            print(f"Failed to flush iptables rules. Error: {e}")

    except OSError as e:
        if e.errno == 98:
            print(f"Address {host}:{port} is already in use. Please try a different port.")
        else:
            print(f"An unexpected error occurred: {e}")
        sys.exit(1)  # Exit the program gracefully



# Example usage:
if __name__ == "__main__":
    if len(sys.argv) > 1:
        param = sys.argv[1].strip().lower()

        if param == "check-all":
            try:
                # Convert second argument to integer and pass to iptableGeneratorTest
                test_value = sys.argv[2].strip()
                test_value = int(sys.argv[2].strip())
                print(test_value)
                iptableGeneratorTest(test_value)
            except ValueError:
                print("Invalid number provided for iptableGeneratorTest. Please provide an integer.")
        elif param == "test":
            generator = IptableRuleGenerator()
            generator.find_or_generate_rule([sys.argv[2].strip()])
        elif param == "start":
            startWebSocket()


