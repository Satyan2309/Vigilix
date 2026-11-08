from app.services.rag import HashingEmbeddings


def test_hashing_embeddings_are_fixed_dimension_and_deterministic():
    embeddings = HashingEmbeddings(n_features=128)
    first = embeddings.embed_documents(["AWS CloudTrail logging changes"])[0]
    second = embeddings.embed_query("AWS CloudTrail logging changes")
    assert len(first) == 128
    assert first == second
