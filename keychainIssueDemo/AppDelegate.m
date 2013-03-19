//
//  AppDelegate.m
//
// Quick example to debug a key chain issue.
//
// https://developer.apple.com/library/mac/#documentation/security/Reference/keychainservices/Reference/reference.html
//
// Assumptions
//
// - Upon adding/removing a keychain in the keychain.app
//   one expect a single kSecKeychainListChangedEvent event
//   for each add/remove which contains at the very least
//   a filled out keychain pointer in the SecKeychainCallbackInfo*
//   passed.
//
// - Upon inserting/removing a chipcard, Kerberos stash or similar
//   keychain bridged security realm - one would expect the same.
//
// Observations
//
// - On adding/removing a keychain file one gets indeed a single
//   keychain event -- but with a 0x0 pointer in keychain.
//
// - On adding/removing a chipcard, token, kerberos KAC one gets
//   some 12 tot 150 kSecKeychainListChangedEvent in quick succession
//   each with a 0x0 pointer for both the keychain and item in the
//   SecKeychainCallbackInfo struct passed in the callback.
//
// Tried on 10.8.3
//

#import "AppDelegate.h"
#import <Security/Security.h>

@implementation AppDelegate

static int cnt = 0;
OSStatus cb(SecKeychainEvent keychainEvent,
            SecKeychainCallbackInfo *cbInfo,
            void *context)
{
    switch(keychainEvent) {
        case kSecAddEvent:
            NSLog(@"kSecAddEvent");
            return noErr;
        case kSecDeleteEvent:
            NSLog(@"kSecDeleteEvent");
            return noErr;
            break;
        case kSecUpdateEvent:
            NSLog(@"kSecUpdateEvent");
            return noErr;
            break;
        case kSecKeychainListChangedEvent:
            NSLog(@"kSecKeychainListChangedEvent %d", ++cnt);
            break;
        default:
            NSLog(@"Unknown event %d", keychainEvent);
            return noErr;
            break;
    }

    if (cbInfo->keychain == nil) {
        NSLog(@"Keychain passed is 0x - giving up (and info is %p)", cbInfo->item);
        return noErr;
    }
    
    char path[16*1024];
    UInt32 len = sizeof(path);
    OSErr err;
    
    err = SecKeychainGetPath(cbInfo->keychain, &len, path);
    if (err != noErr) {
        NSLog(@"Fail on SecKeychainGetPath");
        return err;
    }
    
    if (cbInfo->item == nil) {
        NSLog(@"Item ref passed is 0x - giving up.");
        return noErr;
    }
    
    SecItemClass itemClass = 0;
    err = SecKeychainItemCopyAttributesAndData(cbInfo->item, NULL, &itemClass, NULL, NULL, NULL);
    if (err != noErr) {
        NSLog(@"Fail on SecKeychainItemCopyAttributesAndData %d",err);
        return err;
    }
    
    switch (itemClass)
    {
        case kSecInternetPasswordItemClass:
            itemClass = CSSM_DL_DB_RECORD_INTERNET_PASSWORD;
            break;
        case kSecGenericPasswordItemClass:
            itemClass = CSSM_DL_DB_RECORD_GENERIC_PASSWORD;
            break;
        case kSecAppleSharePasswordItemClass:
            itemClass = CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD;
            break;
        default:
            break;
    }
    

    SecKeychainAttributeInfo * info = NULL;
    err = SecKeychainAttributeInfoForItemID(
                                            cbInfo->keychain,
                                            itemClass,
                                            &info);

    if (err != noErr) {
        NSLog(@"Fail on SecKeychainAttributeInfoForItemID: %d ", err);
        return err;
    }
    SecKeychainAttributeList *attrList = NULL;
    UInt32 length = 0;
    void *outData = nil;
    err = SecKeychainItemCopyAttributesAndData(cbInfo->item,
                                               info,
                                               &itemClass,
                                               &attrList,
                                               &length,
                                               &outData);

    if (err != noErr) {
        NSLog(@"Fail on SecKeychainItemCopyAttributesAndData %d", err);
        return err;
    }

    for(int i = 0; i < attrList->count; i++) {
        SecKeychainAttribute attr = attrList->attr[i];
        NSLog(@"%@ %@",tag2str(attr.tag),
              [[NSString alloc] initWithData:[NSData dataWithBytes:attr.data length:attr.length]
                encoding:NSUTF8StringEncoding]);
    }
    SecKeychainItemFreeAttributesAndData(attrList, outData);
    SecKeychainFreeAttributeInfo(info);
    
    return noErr;
}

NSString * tag2str(SecKeychainAttrType tag) {
    NSMutableString * str = [NSMutableString string];
    if (tag == kSecKeyApplicationTag)
        return @"appt";
    if (tag == kSecKeyKeyCreator)
        return @"crea";
    for(int i =0; i < sizeof(tag); i++) {
        int c = ((char *)&tag)[i];
        if (isprint(c))
            [str appendFormat:@"%c", c];
        else
            [str appendFormat:@"-0x%02X-", c];
    }
    return str;
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    OSStatus err = SecKeychainAddCallback(&cb, kSecKeychainListChangedMask,nil);
    if (err != noErr) {
        NSLog(@"Drat - Fail on SecKeychainAddCallback: %d",err);
        exit(1);
    }
}

-(void)applicationWillTerminate:(NSNotification *)notification {
    SecKeychainRemoveCallback(&cb);
}
@end


//
// Copyright 2013 Dirk-Willem van Gulik <dirkx@webweaving.org>,
//           All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


