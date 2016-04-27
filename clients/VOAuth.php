<?php

namespace aradiv\authclientv\clients;

use yii\authclient\OAuth2;
use yii\authclient\InvalidResponseException;
use yii\helpers\ArrayHelper;
use yii\web\HttpException;
use Yii;
class VOAuth extends OAuth2
{
    /**
     * @inheritdoc
     */
    public $authUrl = 'https://v.enl.one/oauth/authorize';
    /**
     * @inheritdoc
     */
    public $tokenUrl = 'https://v.enl.one/oauth/token';
    /**
     * @inheritdoc
     */
    public $apiBaseUrl = 'https://v.enl.one/oauth/api/v1';
    /**
	* scopes that are used to generate composed userinfos
	*/ 
    private $_userinfoscopes = ['profile', 'email', 'telegram', 'googledata'];
    
	/**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        if ($this->scope === null) {
            $this->scope = implode(' ', [
                'profile',
                'openid'
            ]);
        }
    }
    
    /**
    *  @inheritdoc
    */
    public function buildAuthUrl(array $params = [])
    {
        $authState = $this->generateAuthState();
        $this->setState('authState', $authState);
        $params['state'] = $authState;
        return parent::buildAuthUrl($params);
    } 
    /**
     * @inheritdoc
     */
    public function fetchAccessToken($authCode, array $params = [])
    {
        $authState = $this->getState('authState');
        if (!isset($_REQUEST['state']) || empty($authState) || strcmp($_REQUEST['state'], $authState) !== 0) {
            throw new HttpException(400, 'Invalid auth state parameter.');
        } else {
            $this->removeState('authState');
        }
        return parent::fetchAccessToken($authCode, $params);
    }
	
    /**
     * @inheritdoc
     */
    protected function initUserAttributes()
    {
        $data = [];
        foreach(explode(" ", $this->scope) as $scope){
            if(in_array($scope,$this->_userinfoscopes)){
                $api=$this->api($scope, 'GET');
                if(ArrayHelper::getValue($api,'status') !== "ok"){
                    Yii:trace("Server error: ". print_r($api,true));
                    throw new InvalidResponseException($api, "error", print_r($api,true));
                }
                $apiData = ArrayHelper::getValue($api,'data', []);
                if($scope === "profile"){
                    if(ArrayHelper::getValue($apiData,'blacklisted') !== false || ArrayHelper::getValue($apiData, 'quarantine') !== false || ArrayHelper::getValue($apiData, 'verified') !== true){
                        Yii::trace("OAuth Failed. Provider V. Data: ". print_r($api,true), 'oauth');
                        throw new UserNotAllowedException("User is blacklisted, quarantined or not verified");
                    }
                    if(ArrayHelper::keyExists('enlid', $apiData)){
                        if(ArrayHelper::getValue($apiData, 'enlid') === "null"){
                            Yii:trace("enlid is null", 'oauth');
                            throw new UserNotAllowedException("Userprofile incomplete");
                        }else{
                            $data['id'] = ArrayHelper::getValue($data, 'enlid');
                        }
                    }
                }
                $data = array_merge($data, $apiData);
            }
        }
        return $data;
    }
	
    /**
     * @inheritdoc
     */
    protected function defaultReturnUrl()
    {
        $params = $_GET;
        unset($params['code']);
        unset($params['state']);
        $params[0] = Yii::$app->controller->getRoute();
        return Yii::$app->getUrlManager()->createAbsoluteUrl($params);
    }
    
    protected function defaultName()
    {
        return 'v';
    }

    protected function defaultTitle()
    {
        return 'V';
    }

    protected function defaultViewOptions()
    {
        return [
            'popupWidth' => 800,
            'popupHeight' => 500,
        ];
    }

    /**
     * @inheritdoc
     */
    protected function apiInternal($accessToken, $url, $method, array $params, array $headers)
    {
        array_push($headers,"Authorization: Bearer ".$accessToken->getToken());
        return $this->sendRequest($method, $url, $params, $headers);
    }

    
    /**
    * generate a unique state
    */
    private function generateAuthState(){
        return sha1(uniqid(get_class($this),true));
    }
}
