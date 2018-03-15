/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.opensaml.compat;

import java.util.List;

/**
 * A metadata provider that provides event notification to observers. This may be used, for example, to signal an update
 * of an internal cache of metadata allowing other subsystems to perform some action based on that.
 *
 */
public interface ObservableMetadataProvider extends org.opensaml.compat.MetadataProvider {

    /**
     * Gets the list of observers for the provider. New observers may be added to the list or old ones removed.
     *
     * @return the list of observers
     */
    public List<Observer> getObservers();

    /**
     * An observer of metadata provider changes.
     *
     * <strong>NOTE:</strong> The metadata provider that has changed is passed in to the
     * {@link #onEvent(MetadataProvider)} method. Observers should <strong>NOT</strong> keep a reference to this
     * provider as this may prevent proper garbage collection.
     */
    public interface Observer {

        /**
         * Called when a provider signals an event has occured.
         *
         * @param provider the provider being observed
         */
        public void onEvent(MetadataProvider provider);
    }
}