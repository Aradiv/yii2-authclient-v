<?php

namespace aradiv\authclientv\clients;

use yii\authclient\OAuth2;

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
    public $apiBaseUrl = 'https://v.enl.one/oauth/api/v1/';

	public function init()
    {
        parent::init();
        if ($this->scope === null) {
            $this->scope = implode(' ', [
                'profile',
            ]);
        }
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
	
	protected function initUserAttributes()
    {
		$data = [];
		foreach(explode(" ", $this->scope) as $scope){
			$data = array_merge($data, $this->api($scope, 'GET')['data']);
		}
		if(array_key_exists('enlid', $data)){
			$data['id'] = $data['enlid'];
		}
		return $data;
    }
}