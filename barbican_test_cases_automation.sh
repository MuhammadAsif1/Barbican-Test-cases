#!/bin/bash

################## ------- Varibales ----------###################
###-- 3 compute nodes ---##
compute_node1_ip='192.168.10.140'
compute_node2_ip='192.168.10.140'
compute_node3_ip='192.168.10.140'
###-- 3 controller nodes ---##
controller_node1_ip='192.168.10.140'
controller_node2_ip='192.168.10.140'
controller_node3_ip='192.168.10.140'
barbican_parameter='command' # value of this parameter ----> castellan.key_manager.barbican_key_manager.BarbicanKeyManager
#verify glance is configured to use barbican

volume_template='LuksEncryptor-Template-256'
encrypted_volume='Encrypted-Test-Volume'
private_key='private_key.pem'
public_key='public_key.pem'
cert_request='cert_request.csr'
signed_cert='x509_signing_cert.crt'
singned_cert_key='signing-cert'
cloud_file='cirros-0.4.0-x86_64-disk.img'
signing_image='cirros-0.4.0.signature'
signing_image_b64='cirros-0.4.0.signature.b64'
uuid='nothing'
image='cirros_0_4_0_signed'
network='network1'
subnet='subnet1'
router='router1'
public_network='public'
public_subnet='public-subnet'
flavor='flavor1'
security_group='----------'
instance='barbican_instance'
############################################## ---- Functions ---------#####################################################
verify_glance_with_barbican()
{
  output1=$(ssh osm@$compute_node1_ip 'cat /var/lib/config-data/puppet-generated/glance_api/etc/glance/glance-api.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager') # this should be executed for that ----> cat /var/lib/config-data/puppet-generated/glance_api/etc/glance/glance-api.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager
  	
  output2=$(ssh osm@$compute_node2_ip 'cat /var/lib/config-data/puppet-generated/glance_api/etc/glance/glance-api.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  
  output3=$(ssh osm@$compute_node3_ip 'cat /var/lib/config-data/puppet-generated/glance_api/etc/glance/glance-api.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  
  if [ $barbican_parameter = $output1 ] && [ $barbican_parameter = $output2 ] && [ $barbican_parameter = $output3 ]
  then
    echo $output
    echo '========================================================================================='
    echo '========== Test Case executed Successfully, Glance is enabled to use Barbican ==========='
    echo '========================================================================================='
  else
    echo '========================================================================================='
    echo '=============== Test Case Failed, Glance is not enabled to use Barbican ================='
    echo '========================================================================================='
  fi   
}
#########################################################################
verify_cinder_uses_barbican()
{
  output1=$(ssh osm@$controller_node1_ip 'cat /var/lib/config-data/puppet-generated/cinder/etc/cinder/cinder.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager') # this should be executed for that ----> 'cat /var/lib/config-data/puppet-generated/cinder/etc/cinder/cinder.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager
  
  output2=$(ssh osm@$controller_node2_ip 'cat /var/lib/config-data/puppet-generated/cinder/etc/cinder/cinder.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  
  output3=$(ssh osm@$controller_node1_ip 'cat /var/lib/config-data/puppet-generated/cinder/etc/cinder/cinder.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  
  if [ $barbican_parameter = $output1 ] && [ $barbican_parameter = $output2 ] && [ $barbican_parameter = $output3 ]
  then
    echo $output
    echo '========================================================================================='
    echo '========== Test Case executed Successfully, Cinder is enabled to use Barbican ==========='
    echo '========================================================================================='
  else
    echo '========================================================================================='
    echo '=============== Test Case Failed, Cinder is not enabled to use Barbican ================='
    echo '========================================================================================='
  fi   
}
###########################################################################
verify_nova_uses_barbican()
{
  output1=$(ssh osm@$compute_node1_ip 'cat /var/lib/config-data/nova-libvirt/etc/nova/nova.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager') # this should be executed for that ----> ' cat /var/lib/config-data/nova-libvirt/etc/nova/nova.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager
  output2=$(ssh osm@$compute_node2_ip 'cat /var/lib/config-data/nova-libvirt/etc/nova/nova.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  output3=$(ssh osm@$compute_node3_ip 'cat /var/lib/config-data/nova-libvirt/etc/nova/nova.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  if [ $barbican_parameter = $output1 ] && [ $barbican_parameter = $output2 ] && [ $barbican_parameter = $output3 ]
  then
    echo $output
    echo '========================================================================================='
    echo '========== Test Case executed Successfully, Cinder is enabled to use Barbican ==========='
    echo '========================================================================================='
  else
    echo '========================================================================================='
    echo '=============== Test Case Failed, Cinder is not enabled to use Barbican ================='
    echo '========================================================================================='
  fi   
}
############################################################################
encrypted_volume_creation()
{
  openstack volume type create --encryption-provider nova.volume.encryptors.luks.LuksEncryptor --encryption-cipher aes-xts-plain64 --encryption-key-size 256 --encryption-control-location front-end $volume_template
  openstack volume create --size 1 --type LuksEncryptor-Template-256 $encrypted_volume
  sleep 1m
  output=$(openstack volume show $encrypted_volume | grep available )
  if [ $output = '| status                         | available                             |']
  then
    echo '========================================================================================='
    echo '================= Test Case executed Successfully, Encrypted Volume is created ===================='
    echo '========================================================================================='
  else
    echo '========================================================================================='
    echo '======================= Test Case Failed, Encrypted volume not created ============================'
    echo '========================================================================================='
  fi
  volume_id=$(openstack volume show $encrypted_volume | grep -w id)
}
#################################################################################
verify_addition_of_key_to_barbican_secret_store()
{
  ##Generate a private key and convert it to the required format
  openssl genrsa -out $private_key 1024
  openssl rsa -pubout -in $private_key -out $public_key
  openssl req -new -key $private_key -out $cert_request
  openssl x509 -req -days 14 -in $cert_request -signkey $private_key -out $signed_cert
  ##Add the key to the barbican secret store
  openstack secret store --name $singned_cert_key --algorithm RSA --secret-type certificate --payload-content-type "application/octet-stream" --payload-content-encoding base64  --payload "$(base64 x509_signing_cert.crt)" -c 'Secret href' -f value  ###some doubts in this command
  ###
  echo '=== Record the resulting UUID for use in a later step. for in href uuid will be like 5df14c2b-f221-4a02-948e-48a61edd3f5b ==='
  echo 'Enter uuid = '
  read uuid 
  echo '==== if signed key shown than test case executed successfully otherwise failed ========='
  openstack secret show $singned_cert_key | grep $singned_cert_key
}
####################################################################################
creating_signed_image()
{
  #verify_addition_of_key_to_barbican_secret_store #call function inside it, if needed
  ##Use private_key.pem to sign the image and generate the .signature file
  openssl dgst -sha256 -sign $private_key -sigopt rsa_padding_mode:pss -out $signing_image $cloud_file
  ##Convert the resulting .signature file into base64 format
  base64 -w 0 $signing_image  > $signing_image_b64
  ###Load the base64 value into a variable to use it in the subsequent command
  image_signature_b64=$(cat $signing_image_b64)
  ##### Upload the signed image to glance. For img_signature_certificate_uuid, you must specify the UUID of the signing key you previously uploaded to barbican
  openstack image create --container-format bare --disk-format qcow2 --property img_signature='$image_signature_b64' --property img_signature_certificate_uuid=$uuid --property img_signature_hash_method='SHA-256' --property img_signature_key_type='RSA-PSS' $image < $cloud_file
}
###################################################################################

###################################################################################
creating_network_and_server()
{
  openstack network create $network
  openstack subnet create $subnet --network $network --subnet-range 192.168.50.0/24
  openstack router create $router
  openstack router set $router --external-gateway $public_network
  ###Adding Public Subnet to Router
  openstack router add subnet $router $public_subnet
  ### Creating Port in $network
  openstack port create --network $network --fixed-ip subnet=$subnet,ip-address=192.168.50.40 port1
  openstack router add subnet $router $subnet
  ### creating keypair
  openstack keypair create barbican_keypair >> barbican_keypair.pem
  ### creating server
  openstack server create --flavor $flavor --image $image --key-name barbican_keypair --security-group $security_group --network $network $instance
  sleep 1m
  output=$(openstack server show $instance | grep status )
  if [ $output = '| status                              | ERROR                                                                                                                                                                                                                                                                                                                                                                                        |']
  then
    echo '========================================================================================='
    echo '===================== Instance created  Created successfully ============================'
    echo '========================================================================================='
    openstack floating ip create $public_network
    #assign floating ip to instance
    echo '=========== List of Floating IPs =============='
    openstack floating ip list
    echo 'Enter created floating ip = '
    read Floating_IP
    openstack server add floating ip $instance $Floating_IP
    output=$(ping -c 1 $Floating_IP &> /dev/null && echo success || echo fail)
    if [ $output = 'success']
    then
      echo '=========================== instance is reachable from external network ==========='
      ping $Floating_IP
    else 
      echo '=========================== ping unsuccessfull, test case failde ==========='
      ping $Floating_IP
  else
    echo '========================================================================================='
    echo '======================= Test Case Failed, Encrypted Instance not created ============================'
    echo '========================================================================================='
  fi
}
###################################################################################
attach_encrypted_volume_to_existing_instance()
{
  openstack server add volume $instance $encrypted_volume
}
#############---------- Main ------------#############

#verify_glance_with_barbican
#verify_cinder_uses_barbican
#verify_nova_uses_barbican
#encrypted_volume_creation
#verify_addition_of_key_to_barbican_secret_store ## this should be called in 'creating_signed_image', if needed 
#creating_signed_image
#creating_network_and_server
#attach_encrypted_volume_to_existing_instance
