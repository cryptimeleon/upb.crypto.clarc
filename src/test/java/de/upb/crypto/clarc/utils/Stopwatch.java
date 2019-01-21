package de.upb.crypto.clarc.utils;

public class Stopwatch {
	private String name;
	private long start;
	private long elapsedTime;

	private boolean running;

	public Stopwatch(String name) {
		this.name = name;
		this.running = false;
		reset();
	}

	public void start() {
		if(running)
			System.out.println("Timer already running");
		else {
			this.start = System.nanoTime();
			running = true;
		}
	}

	public void stop() {
		if(!running)
			System.out.println("Timer is not running!");
		else {
			this.elapsedTime += System.nanoTime() - start;
			running = false;
		}
	}

	public void reset() {
		this.elapsedTime = 0;
		this.running = false;
	}



	public void print() {
		System.out.println(this.toString());
	}

	@Override
	public String toString() {
		return name + " , " + ((double) elapsedTime) / 1E9;
	}

	public long timeElapsed() {
		return this.elapsedTime;
	}
}
