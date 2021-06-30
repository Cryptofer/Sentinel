<?php

class Captcha {
    protected $session = array(
        'folder_path'       => null,
        'total_icons'       => 0,
        'hashes'            => array(),
        'icon_requests'     => 0,
        'correct_icon'      => null,
        'incorrect_icon'    => null,
        'noise'             => 0
    );

    public $available = false; // Determines whether the captcha is good to use or not.

    public function createSession() {
        $this->incorrect_icon = 0;
        $this->correct_icon = mt_rand(1, $this->session['total_icons']);

        while($this->incorrect_icon === 0) {
            $random = mt_rand(1, $this->session['total_icons']);

            if($random !== $this->correct_icon) {
                $this->incorrect_icon = $random;
            }
        }

        $icon_array = $this->shuffleIcons();
        $hash_array = array();
        for($i = 0; $i < 5; $i++) {
            $hash = $this->getHash("icon-" . $icon_array[$i] . "-" . $i);

            $hash_array[$hash] = $icon_array[$i];
        }

        $this->session['hashes'] = $hash_array;
        $this->session['icon_requests'] = 0;
        $this->session['correct_icon'] = $this->correct_icon;
        $this->session['incorrect_icon'] = $this->incorrect_icon;

        $this->saveSession();
    }

    public function validateInput($input) {

        if(empty($input) || !is_array($input) || count($input) === 0 || !isset($_SESSION['icon_captcha'])) {
            return false;
        }

        $this->session = $_SESSION['icon_captcha'];
        $correct_icons_count = 0;

        foreach($input as $raw_hash) {
            //Clean the hash
            $hash = preg_replace("/[^a-zA-Z0-9]+/", "", $raw_hash);

            //Check whether the hash exists in our current session, to avoid missing key errors
            if(!array_key_exists($hash, $this->session['hashes'])) {
                return false;
            }

            //Check whether an incorrect icon is selected
            if($this->session['hashes'][$hash] === $this->session['incorrect_icon']) {
                return false;
            }

            if($this->session['hashes'][$hash] === $this->session['correct_icon']) {
                $correct_icons_count++;
            }
        }

        if($correct_icons_count < 2) {
            return false;
        }

        return true;
    }

    public function getCaptcha() {

        header('Content-type: image/png');
        header('Expires: 0');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Cache-Control: post-check=0, pre-check=0', false);
        header('Pragma: no-cache');

        if($_SESSION['icon_captcha']['icon_requests'] > 0 || !isset($_SESSION['icon_captcha'])) {
            return;
        }
        
        $this->generateSprite();

        $this->session = $_SESSION['icon_captcha']; // Get the current session
        $this->session['icon_requests'] = 1; // Update the session values
        $this->saveSession();
    }

    public function generateSprite() {
        // Create the size of image or blank image
        $sprite = imagecreate(150, 30);
        
        // Set the background color of image
        $background_color = imagecolorallocate($sprite, 255, 255, 255);

        $session = $_SESSION['icon_captcha'];
        $foreach_index = 0;
        foreach($session['hashes'] as $hash => $icon_index) {
            $tmp = imagecreatefrompng($session['folder_path'] . "/icon-" . ($icon_index) . ".png");
            imagecopy($sprite, $tmp, ($foreach_index * 30), 0, 0, 0, 30, 30);
            imagedestroy($tmp);

            $foreach_index++;
        }

        if($session['noise'] > 0) {
            $noise_color = imagecolorallocatealpha($sprite, 0, 0, 0, 126);

            // Add some random pixels to the icon
            for ($i = 0; $i < $session['noise']; $i++) {
                $randX = mt_rand(0, 150);
                $randY = mt_rand(0, 30);

                imagesetpixel($sprite, $randX, $randY, $noise_color);
            }
        }

        imagepng($sprite);
        imagedestroy($sprite);
    }

    protected function shuffleIcons() {
        $hashes = array($this->incorrect_icon, $this->incorrect_icon, $this->incorrect_icon, $this->correct_icon, $this->correct_icon);
        shuffle($hashes);
        return $hashes;
    }

    protected function getHash($image = null) {
        return hash('tiger192,3', $image . hash('crc32b', uniqid('ic_', true)));
    }

    public function setIconsFolderPath($folder_path) {
        $files = glob($folder_path . "/*.png");
        if($files) {
            $this->session['folder_path'] = $folder_path;
            $this->session['total_icons'] = count($files);
        }
    }

    public function addNoise($amount) {
        $this->session['noise'] = (int)$amount;
    }

    public function hashArray() {
        return $this->session['hashes'];
    }

    public function saveSession() {
        $_SESSION['icon_captcha'] = $this->session;
    }

}

?>