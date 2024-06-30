import torch
import pandas as pd
from transformers import GPT2Tokenizer, GPT2LMHeadModel
import random

links_df=pd.read_csv("phishing_links.csv")
links=links_df['url'].tolist()

# Load the tokenizer and model
tokenizer = GPT2Tokenizer.from_pretrained("phishing_email_generator")
model = GPT2LMHeadModel.from_pretrained("phishing_email_generator")

# Move the model to the appropriate device
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model.to(device)

def generate_email(prompt):
    inputs = tokenizer.encode(prompt, return_tensors='pt', padding=True, truncation=True)
    inputs = inputs.to(device)  # Move inputs to the same device as the model
    
    outputs = model.generate(
        inputs,
        max_length=200,
        num_return_sequences=1,
        pad_token_id=tokenizer.eos_token_id,
        do_sample=True,
        temperature=0.7,  # Controls the randomness of predictions (lower = more deterministic)
        top_k=50,  # Limits the sampling pool to top_k tokens
        top_p=0.9  # Nucleus sampling: samples from the smallest possible set of tokens whose cumulative probability exceeds top_p
    )
    
    generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    # Select a random link from the dataset (assuming links list is loaded)
    random_link = random.choice(links)
    
    # Append the random link and "Thank you" to the generated email
    final_email = f"{generated_text}\n\n{random_link}\n\nThank you."
    
    return final_email