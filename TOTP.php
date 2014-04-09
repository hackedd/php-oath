<?php

require_once "HOTP.php";

/**
 * This class implements the algorithm outlined in RFC 6238:
 * HOTP: Time-Based One-Time Password Algorithm.
 */
class TOTP extends HOTP
{
    /** @var int time step (in seconds) */
    protected $timeStep = 30;

    /** @var int Unix time to start counting time steps */
    protected $epoch = 0;

    public function __construct($key, $digits = 6)
    {
        parent::__construct($key, null, $digits);
    }

    public function getCounter()
    {
        $currentTime = $this->counter !== null ? $this->counter : self::getCurrentTime();
        return (int)floor(($currentTime - $this->epoch) / $this->timeStep);
    }

    public function increment()
    {
        if ($this->counter !== null)
            $this->counter += $this->timeStep;
    }

    /**
     * @param int $epoch
     */
    public function setEpoch($epoch)
    {
        $this->epoch = $epoch;
    }

    /**
     * @return int
     */
    public function getEpoch()
    {
        return $this->epoch;
    }

    /**
     * @param int $timeStep
     */
    public function setTimeStep($timeStep)
    {
        $this->timeStep = $timeStep;
    }

    /**
     * @return int
     */
    public function getTimeStep()
    {
        return $this->timeStep;
    }

    public static function getCurrentTime()
    {
        return time();
    }
}
