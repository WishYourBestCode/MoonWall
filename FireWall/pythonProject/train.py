import json
import torch
from sentence_transformers import SentenceTransformer

# Load your rules data from JSON
with open('iptables2.json', 'r') as file:
    rules_data = json.load(file)

# Initialize the sentence transformer model
model = SentenceTransformer('all-MiniLM-L6-v2')

# Precompute embeddings for the rule descriptions
descriptions = [rule['description'] for rule in rules_data]
description_embeddings = model.encode(descriptions, convert_to_tensor=True)

# Save the embeddings
torch.save(description_embeddings, 'description_embeddings.pt')

# Save the rules data separately
with open('rules_data.json', 'w') as f:
    json.dump(rules_data, f)