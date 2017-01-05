<?php

namespace YAOCO;

class FormHelper {
	/**
	 * Holds the forms built by this class.
	 *
	 * Structure:
	 * array(
	 *   'id1' => array(
	 *     'field_id1' => array(
	 *       'type' => string [username|text|email|address|password|number|date|tel|url|time|bool],
	 *       'label' => string,
	 *       'value' => mixed,
	 *       'message' => string,
	 *       'note' => string,
	 *       'readonly' => bool,
	 *       'required' => bool,
	 *       'valid' => bool
	 *     ),
	 *     ...
	 *   ),
	 *   ...
	 * );
	 *
	 * @var array.
	 */
	private $fields = array( );

	/**
	 * A prefix for the field's ids.
	 *
	 * @var string
	 */
	private $prefix = 'form_';

	public function buildForm( string $id, string $origin, string $destination, array $fields ) {
		if ( ! isset( $_SESSION[ 'oicpserver.formhelper.' . $id ] ) ) {
			$_SESSION[ 'oicpserver.formhelper.' . $id ][ 'fields'	] = $fields;
		}

		// make sure all required fields are available
		foreach ( $fields as $fieldID => $field ) {
			$this->fields[ $id ][ $fieldID ] = array_merge(
				array(
					'type' => 'text',
					'label' => 'label',
					'value' => '',
					'message' => '',
					'note' => '',
					'readonly' => false,
					'required' => false,
					'valid' => true
				),
				$_SESSION[ 'oicpserver.formhelper.' . $id ][ 'fields' ][ $fieldID ]
			);
		}

		// persist the form in the session
		$_SESSION[ 'oicpserver.formhelper.' . $id ] = array(
			'destination' => $destination,
			'origin' => $origin,
			'fields' => $this->fields[ $id ]
		);

		return $_SESSION[ 'oicpserver.formhelper.' . $id ];
	}

	public function checkForm( string $id, $request ) {
		if ( ! isset( $_SESSION[ 'oicpserver.formhelper.' . $id ] ) ) {
			return false;
		}
		// get information about the fields from the session
		$this->fields[ $id ] = $_SESSION[ 'oicpserver.formhelper.' . $id ][ 'fields' ];
		$origin = $_SESSION[ 'oicpserver.formhelper.' . $id ][ 'origin' ];
		$destination = $_SESSION[ 'oicpserver.formhelper.' . $id ][ 'destination' ];
		unset( $_SESSION[ 'oicpserver.formhelper.' . $id ] );
		$valid = true;

		foreach ( $this->fields[ $id ] as $fieldID => $field ) {
			$checkerFunction = 'check' . ucfirst( $field[ 'type' ] );
			$this->fields[ $id ][ $fieldID ][ 'message' ] = '';
			$this->fields[ $id ][ $fieldID ][ 'value' ] = $this->$checkerFunction( $request->get( $fieldID ) );
			$this->fields[ $id ][ $fieldID ][ 'valid' ] = true;

			if ( $this->fields[ $id ][ $fieldID ][ 'value' ] === null ) {
				// invalid user input
				$this->fields[ $id ][ $fieldID ][ 'message' ] = 'Please correct the value.';
				$this->fields[ $id ][ $fieldID ][ 'valid' ] = false;
				$valid = false;
			}

			if ( empty( $request->get( $fieldID ) ) && $this->fields[ $id ][ $fieldID ][ 'required' ] ) {
				// missing value
				$this->fields[ $id ][ $fieldID ][ 'message' ] = 'Missing value.';
				$this->fields[ $id ][ $fieldID ][ 'valid' ] = false;
				$valid = false;
			}
		}
		// store the data in a session (but don't store the passwords)
		$_SESSION[ 'oicpserver.formhelper.' . $id ] = array(
			'fields' => $this->fields[ $id ],
			'origin' => $origin,
			'destination' => $destination
	 	);
		foreach ( $this->fields[ $id ] as $fieldID => $field ) {
			if ( $field[ 'type' ] === 'password' ) {
				$_SESSION[ 'oicpserver.formhelper.' . $id ][ 'fields' ][ $fieldID ][ 'value' ] = '';
			}
		}

		return $valid;
	}

	public function getFormData( string $id ) {
		if ( ! isset( $_SESSION[ 'oicpserver.formhelper.' . $id ] ) ) {
			return array( );
		}

		return array(
			'origin' => $_SESSION[ 'oicpserver.formhelper.' . $id ][ 'origin' ],
			'destination' => $_SESSION[ 'oicpserver.formhelper.' . $id ][ 'destination' ],
			// we cannot use $_SESSION[ 'oicpserver.formhelper.' . $id ][ 'fields' ]
			// as the passwords are not stored in there
			'fields' => $this->fields[ $id ]
		);//$_SESSION[ 'oicpserver.formhelper.' . $id ];
	}

	public function setMessageForField( string $id, string $fieldID, string $message ) {
		if ( isset( $_SESSION[ 'oicpserver.formhelper.' . $id ] ) &&
			isset( $_SESSION[ 'oicpserver.formhelper.' . $id ][ 'fields' ][ $fieldID ] ) ) {
			$_SESSION[ 'oicpserver.formhelper.' . $id ][ 'fields' ][ $fieldID ][ 'message' ] = $message;
		}
	}

	public function clearFormData( string $id ) {
		unset( $_SESSION[ 'oicpserver.formhelper.' . $id ] );
	}

	private function checkText( string $value ) {
		//if ( $value === '' ) {
		//	return null;
		//}
		return htmlspecialchars( $value );
		return mysqli_real_escape_string( htmlspecialchars( $value ) );
	}

	private function checkUsername( string $value ) {
		return $this->checkText( $value );
	}

	private function checkUrl( string $value ) {
		return $this->checkText( $value );
	}

	private function checkEmail( string $value ) {
		return $this->checkText( $value );
	}

	private function checkAddress( string $value ) {
		return $this->checkText( $value );
	}

	private function checkNumber( string $value ) {
		if ( is_numeric( $value ) ) {
			return $value;
		}
		return null;
	}

	private function checkPassword( string $value ) {
		return $this->checkText( $value );
	}

	private function checkTime( string $value ) {
		return $this->checkText( $value );
	}

	private function checkTel( string $value ) {
		return $this->checkText( $value );
	}

	private function checkDate( string $value ) {
		return $this->checkText( $value );
	}

	private function checkBool( string $value ) {
		return ( bool ) $value;
	}
}
