<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="./style.css" type="text/css" />
    <title>Icon Captcha</title>
    <style>
        .captcha-icon {
            background-image: url('captcha-img.php');
            background-repeat: no-repeat;
            width: 30px;
            height: 30px;
        }

        .captcha-icon.icon-1 {
            background-position: 0 0;
        }

        .captcha-icon.icon-2 {
            background-position: -30px 0;
        }

        .captcha-icon.icon-3 {
            background-position: -60px 0;
        }

        .captcha-icon.icon-4 {
            background-position: -90px 0;
        }

        .captcha-icon.icon-5 {
            background-position: -120px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        
        <?php

        $Captcha = new Captcha();
        $Captcha->setIconsFolderPath("./icons");
        $Captcha->addNoise(1000);

        if(isset($_POST['submit'])) {
            if(!isset($_POST['captcha']) || !$Captcha->validateInput($_POST['captcha'])) {
                echo "Invalid captcha";
            } else {
                //Create our sentinel session
                $Sentinel->createSession();
                header("Location: index.php"); //Refresh the page
            }
        }

        $Captcha->createSession();
        $captcha_values = $Captcha->hashArray();

        ?>

        <form action="" method="POST">
            <div class="captcha-holder">
                <div class="captcha-title">
                    Select the image(s) that do not belong in the row
                </div>
                <div class="captcha-icons">
                    <?php
                        $index = 1;
                        foreach($captcha_values as $hash => $image):
                            ?>

                    <label class="captcha-selector" for="icon-<?php echo $index; ?>">
                        <div class="captcha-checkbox">
                            <input type="checkbox" id="icon-<?php echo $index; ?>" name="captcha[]" value="<?php echo $hash; ?>">
                            <span class="check"></spam>
                        </div>
                        <div class="captcha-icon icon-<?php echo $index; ?>"></div>
                    </label>

                            <?php
                            $index++;
                        endforeach;

                    ?>
                </div>
            </div>
            <div style="margin-top: 1em; text-align: center">
                <button type="submit" name="submit">Validate captcha</button>
            </div>
        </form>
    </div>
</body>
</html>