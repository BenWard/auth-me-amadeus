<?php

/* AUTH ME AMADEUS! */

/* This is a simple tool to take a user through the OAuth process on provision
   of an Application Consumer Key *and* and Application Secret. They are taken
   through the auth process, and come out with an authed user token. */

require('lib/fireeagle.php');

/* Submitted Application IDs */
if (isset($_GET['app-consumer']) && isset($_GET['app-secret'])) {
    
    $fe = new FireEagle($_GET['app-consumer'], $_GET['app-secret']);
    $tok = $fe->getRequestToken();
      if (!isset($tok['oauth_token'])
          || !is_string($tok['oauth_token'])
          || !isset($tok['oauth_token_secret'])
          || !is_string($tok['oauth_token_secret'])) {
       echo "ERROR! FireEagle::getRequestToken() returned an invalid response. Giving up.";
       exit;
      }
      
      $sess['app_consumer'] = $_GET['app-consumer'];
      $sess['app_secret'] = $_GET['app-secret'];
      $sess['auth_state'] = "start";
      $sess['request_token'] = $token = $tok['oauth_token'];
      $sess['request_secret'] = $tok['oauth_token_secret'];
            
      setcookie('amadeus_request', base64_encode(serialize($sess)));
      
      header("Location: ".$fe->getAuthorizeURL($token).'&oauth_callback=http://amadeus.benapps.net');
      exit;
}
else {
    // We're Going to be rendering something:
?>
<!DOCTYPE html>
<title>Auth me, Amadeus!</title>
<style type="text/css">
    body {
        width: 30em;
        margin: 10px auto;
    }
    
    fieldset {
        border: 1px #5F7A99 solid;
        -webkit-border-radius: 10px;
        -moz-border-radius: 10px;
        border-radius: 10px;
        margin: 10px 0;
    }
    
    form label {
        display: block;
        font-size: 80%;
        font-weight: bold;
    }
    
</style>
<h1>Auth me, Amadeus!</h1>
<?php
    if(isset($_GET['oauth_token'])) {
        // We have a return! So, get the user key!
        
        $sess = unserialize(base64_decode($_COOKIE['amadeus_request']));
        
        if ($sess['auth_state'] != "start") {
            echo "<p><strong class='error'>OAuth flow out of sequence.</strong> <a href='/'>Start Again</a>.</p>";
            exit;
        }
        
        if ($_GET['oauth_token'] != $sess['request_token']) {
            echo "<p><strong class='error'>OAuth token mismatch</strong>. <a href='/'>Start Again</a>.</p>";
            exit;
        }
        
        $fe = new FireEagle($sess['app_consumer'], $sess['app_secret'], $sess['request_token'], $sess['request_secret']);
        $tok = $fe->getAccessToken();
        
        if (!isset($tok['oauth_token']) || !is_string($tok['oauth_token'])
              || !isset($tok['oauth_token_secret']) || !is_string($tok['oauth_token_secret'])) {
           error_log("Bad token from FireEagle::getAccessToken(): ".var_export($tok, TRUE));
           echo "ERROR! FireEagle::getAccessToken() returned an invalid response. Giving up.";
           exit;
        }
        ?>
        
        <p><em>Awesome</em>, you've authed and now have some user credentials to use in your script.
            <strong>Remember to keep these secret, they are for your personal use only!</strong>.</p>
        
        <dl>
            <dt>User Token:</dt>
            <dd><?php echo $tok['oauth_token']; ?></dd>
            <dt>User Secret:</dt>
            <dd><?php echo $tok['oauth_token_secret']; ?></dd>
        </dl>
    <?php } 
    else { // We have no token, so ask for keys: ?>
        <p>Hi there, developer. This is a tiny little utility to auth yourself against
            a Fire Eagle application, given the API keys. This gives you an authed user
            token for yourself, allowing you to make calls from a standalone, static 
            environment; such as a bookmarklet.</p>

        <ol>
            <li>Create a <a href="http://fireeagle.yahoo.net/developer/create">new application</a> on Fire Eagle.</li>
            <li>Enter the keys below to auth with your app, and get your user key.</li>
        </ol>

        <form action="" method="GET">
            <fieldset>
                <label for="fe-consumer-key">Application Consumer Key</label>
                <input id="fe-consumer-key" name="app-consumer" value="<?php echo $_GET['app-consumer'] ?>">

                <label for="fe-secret-key">Application Secret</label>
                <input id="fe-secret-key" name="app-secret" value="<?php echo $_GET['app-secret'] ?>">
            </fieldset>
            <fieldset>
                <input type="submit" name="do-auth" value="Authorize with Fire Eagle">
            </fieldset>
        </form>
        <p><strong>This is just an aid to build your own standalone scripts in
            environments that you can't store credentials. you should not be
            giving your application secret to any actual users!</strong>
            Credentials are not stored.</p>    
    <?php }
    
    ?>

    <footer>
        <small>Created by Ben Ward. Code available on GitHub 
        <a href="http://github.com/BenWard/auth-me-amadeus/">http://github.com/BenWard/auth-me-amadeus/</a>.
    </footer>
    <?php
    
} ?>