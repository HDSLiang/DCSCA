package com.example.sca.ui.cloud.encryptalgorithm.trabe.benchmark;

import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbeSecretMasterKey;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.Cpabe;

import java.util.UUID;

public class CpabeKeygenAttributeNumberTest extends Benchmark {
	private AbeSecretMasterKey msk;

	private String attributes = "";
	
	
	@Override
	public void initializeIteration(int iteration) {
		attributes = UUID.randomUUID().toString();
		for (int i = 0; i < iteration; i++) {
			attributes += " " + UUID.randomUUID();
		}
	}
	
	@Override
	public void singleRun(int iteration) {
		try {
			Cpabe.keygenSingle(msk, attributes);
		} catch (Exception e) {
			throw new RuntimeException("exception thrown during test", e);
		}
	}

	@Override
	public void initializeBenchmark() {
		msk = Cpabe.setup(numIterations() * numRunsPerIteration() + numWarmupRuns());
	}

	@Override
	public int numWarmupRuns() {
		return 5;
	}

	@Override
	public int numIterations() {
		return 10;
	}

	@Override
	public int numRunsPerIteration() {
		return 5;
	}

}
